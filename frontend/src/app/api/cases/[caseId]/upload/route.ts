import { NextResponse } from 'next/server';
import crypto from 'crypto';
import { casesStore, StoredFile } from '@/lib/store';

function inspectMagicBytes(buffer: Buffer, originalFilename: string) {
  const ext = originalFilename.includes('.')
    ? '.' + originalFilename.split('.').pop()!.toLowerCase()
    : '';

  let detectedCategory = 'misc';
  let trueType = ext || '.bin';
  let trueMime = 'application/octet-stream';
  let extensionMatch = true;
  let hasTrailing = false;
  let trailingBytes = 0;

  // Check magic bytes
  if (buffer.length >= 2 && buffer[0] === 0x4D && buffer[1] === 0x5A) {
    // MZ (Windows PE Executable)
    detectedCategory = 'executable';
    trueType = '.exe';
    trueMime = 'application/x-dosexec';
  } else if (buffer.length >= 4 && buffer[0] === 0x7F && buffer[1] === 0x45 && buffer[2] === 0x4C && buffer[3] === 0x46) {
    // ELF
    detectedCategory = 'executable';
    trueType = '.elf';
    trueMime = 'application/x-executable';
  } else if (buffer.length >= 4 && buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
    // %PDF
    detectedCategory = 'document';
    trueType = '.pdf';
    trueMime = 'application/pdf';
  } else if (buffer.length >= 3 && buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
    // JPEG
    detectedCategory = 'image';
    trueType = '.jpg';
    trueMime = 'image/jpeg';
  } else if (buffer.length >= 4 && buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
    // PNG
    detectedCategory = 'image';
    trueType = '.png';
    trueMime = 'image/png';
  } else if (buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4B && buffer[2] === 0x03 && buffer[3] === 0x04) {
    // ZIP / Archive
    detectedCategory = 'archive';
    trueType = '.zip';
    trueMime = 'application/zip';
  } else {
    // Text or log heuristics
    const sample = buffer.subarray(0, Math.min(1024, buffer.length)).toString('utf-8');
    const isPrintable = /^[\r\n\t\x20-\x7E]+$/.test(sample);
    if (isPrintable || ext === '.log' || ext === '.syslog' || ext === '.txt') {
      detectedCategory = 'log';
      trueType = ext || '.log';
      trueMime = 'text/plain';
    }
  }

  if (ext && ext !== trueType) {
    // Ignore .jpg vs .jpeg or .txt vs .log
    const interchangeable = new Set(['.jpg', '.jpeg']);
    const textTypes = new Set(['.txt', '.log', '.syslog', '.csv']);
    if (!(interchangeable.has(ext) && interchangeable.has(trueType)) &&
        !(textTypes.has(ext) && textTypes.has(trueType))) {
      extensionMatch = false;
    }
  }

  // Trailing data checks (past JPEG EOI or PNG IEND)
  if (trueType === '.jpg') {
    const eoiIndex = buffer.lastIndexOf(Buffer.from([0xFF, 0xD9]));
    if (eoiIndex !== -1 && eoiIndex + 2 < buffer.length) {
      hasTrailing = true;
      trailingBytes = buffer.length - (eoiIndex + 2);
    }
  }

  // Evaluate risk factors and unverified popup
  const flags: string[] = [];
  const reasons: string[] = [];
  const riskBreakdown: Array<{ factor: string; points: number; evidence_id: string; description: string }> = [];
  let riskScore = 0;

  if (['executable', 'script'].includes(detectedCategory) || ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.sh', '.elf'].includes(trueType)) {
    flags.push('EXECUTABLE_OR_SCRIPT');
    reasons.push(`Executable binary or script detected ('${trueType}'). High execution risk.`);
    riskBreakdown.push({
      factor: 'Executable / Script Detected',
      points: 25,
      evidence_id: 'EVID-EXEC-001',
      description: 'Binary format capable of arbitrary host instruction execution.'
    });
    riskScore += 25;
  }

  if (!extensionMatch) {
    flags.push('EXTENSION_MISMATCH');
    reasons.push(`Claimed extension '${ext}' does not match detected magic bytes '${trueType}' (${trueMime}).`);
    riskBreakdown.push({
      factor: 'Extension / MIME Mismatch',
      points: 15,
      evidence_id: 'EVID-EXT-001',
      description: `File disguises true content type '${trueType}' under extension '${ext}'.`
    });
    riskScore += 15;
  }

  if (hasTrailing) {
    flags.push('TRAILING_DATA_AFTER_EOF');
    reasons.push(`Detected ${trailingBytes} bytes of hidden / trailing payload appended after end-of-file marker.`);
    riskBreakdown.push({
      factor: 'Trailing Data Past EOF',
      points: 25,
      evidence_id: 'EVID-EOF-001',
      description: `Hidden payload (${trailingBytes} bytes) carved past standard terminator.`
    });
    riskScore += 25;
  }

  if (detectedCategory === 'misc' || !['image', 'log', 'document'].includes(detectedCategory)) {
    flags.push('UNVERIFIED_TYPE');
    reasons.push(`File format '${trueType}' is an unverified / miscellaneous type outside standard forensic categories.`);
    riskBreakdown.push({
      factor: 'Miscellaneous / Unverified File Format',
      points: 25,
      evidence_id: 'EVID-MISC-002',
      description: 'Format outside standard image, log, or authenticated document categories.'
    });
    riskScore += 25;
  }

  let verdict: 'Verified-Clean-Looking' | 'Unverified' | 'Suspicious' | 'Likely Malicious' = 'Verified-Clean-Looking';
  if (riskScore >= 50) {
    verdict = 'Likely Malicious';
  } else if (riskScore >= 25) {
    verdict = 'Suspicious';
  } else if (flags.length > 0) {
    verdict = 'Unverified';
  }

  const shouldTrigger = flags.length > 0;
  const unverifiedPopup = shouldTrigger ? {
    should_trigger_popup: true,
    title: '⚠ Miscellaneous / Unverified File Detected',
    warning_text: 'ForensiGPT could not verify this file as safe. It has NOT been scanned by antivirus. Do not open or run it on your main system.',
    reasons,
    claimed_type: ext || 'Unknown',
    detected_true_type: `${trueType} (${trueMime})`,
    verdict,
    persistent_badge: 'UNVERIFIED'
  } : undefined;

  return {
    detectedCategory,
    trueType,
    trueMime,
    extensionMatch,
    hasTrailing,
    trailingBytes,
    flags,
    verdict,
    riskScore,
    riskBreakdown,
    unverifiedPopup
  };
}

export async function POST(
  req: Request,
  { params }: { params: { caseId: string } }
) {
  const caseData = casesStore.get(params.caseId);
  if (!caseData) {
    return NextResponse.json({ detail: 'Case not found' }, { status: 404 });
  }

  try {
    const formData = await req.formData();
    const files = formData.getAll('files') as File[];

    const uploadedFiles: StoredFile[] = [];
    const popupRequired: any[] = [];

    for (const file of files) {
      const arrayBuffer = await file.arrayBuffer();
      const buffer = Buffer.from(arrayBuffer);

      const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');
      const sha1 = crypto.createHash('sha1').update(buffer).digest('hex');
      const md5 = crypto.createHash('md5').update(buffer).digest('hex');

      const analysis = inspectMagicBytes(buffer, file.name);
      const fileId = crypto.randomUUID();

      const storedFile: StoredFile = {
        id: fileId,
        case_id: params.caseId,
        original_filename: file.name,
        file_size: file.size,
        sha256,
        sha1,
        md5,
        mime_type: analysis.trueMime,
        detected_category: analysis.detectedCategory,
        true_file_type: analysis.trueType,
        extension_match: analysis.extensionMatch,
        has_trailing_data: analysis.hasTrailing,
        trailing_bytes_count: analysis.trailingBytes,
        unverified_flags: analysis.flags,
        verdict: analysis.verdict,
        risk_score: analysis.riskScore,
        risk_breakdown: analysis.riskBreakdown,
        uploaded_at: new Date().toISOString(),
        unverified_popup: analysis.unverifiedPopup,
        buffer
      };

      caseData.files.push(storedFile);
      caseData.updated_at = new Date().toISOString();

      // Mask buffer before sending in response
      const { buffer: _, ...publicFile } = storedFile;
      uploadedFiles.push(publicFile as StoredFile);

      if (analysis.unverifiedPopup) {
        popupRequired.push({
          ...analysis.unverifiedPopup,
          file_id: fileId
        });
      }
    }

    return NextResponse.json({
      uploaded_files: uploadedFiles,
      popup_required_files: popupRequired
    });
  } catch (err: any) {
    return NextResponse.json({ detail: err.message }, { status: 500 });
  }
}
