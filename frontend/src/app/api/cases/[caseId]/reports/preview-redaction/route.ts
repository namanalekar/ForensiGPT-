import { NextResponse } from 'next/server';
import { casesStore } from '@/lib/store';

export async function POST(
  req: Request,
  { params }: { params: { caseId: string } }
) {
  const caseData = casesStore.get(params.caseId);
  if (!caseData) return NextResponse.json({ detail: 'Case not found' }, { status: 404 });

  const files = caseData.files.map(f => ({
    filename: f.original_filename,
    sha256: f.sha256,
    verdict: f.verdict,
    risk_score: f.risk_score
  }));

  return NextResponse.json({
    case_id: params.caseId,
    redaction_candidates: [
      {
        field_name: 'internal_ip',
        original_value: '192.168.1.105',
        redacted_value: '[REDACTED_IP]',
        category: 'IP',
        applied: true
      }
    ],
    sanitized_evidence_json: {
      case_title: caseData.title,
      files
    }
  });
}
