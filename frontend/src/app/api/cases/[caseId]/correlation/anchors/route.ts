import { NextResponse } from 'next/server';
import { casesStore } from '@/lib/store';

export async function GET(
  req: Request,
  { params }: { params: { caseId: string } }
) {
  const caseData = casesStore.get(params.caseId);
  if (!caseData) return NextResponse.json({ detail: 'Case not found' }, { status: 404 });

  const filesWithAnchors = caseData.files.map(f => {
    const upDt = new Date(f.uploaded_at);
    return {
      file_id: f.id,
      filename: f.original_filename,
      category: f.detected_category,
      anchors: [
        {
          anchor_type: 'upload_time',
          label: 'File Ingestion / Upload Timestamp',
          iso_timestamp: upDt.toISOString(),
          epoch: upDt.getTime() / 1000,
          source: 'Platform Chain of Custody',
          confidence: 'High'
        }
      ]
    };
  });

  return NextResponse.json({ case_id: params.caseId, files: filesWithAnchors });
}
