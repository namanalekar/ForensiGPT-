import { NextResponse } from 'next/server';
import { casesStore, reportsStore } from '@/lib/store';

export async function POST(
  req: Request,
  { params }: { params: { caseId: string } }
) {
  const caseData = casesStore.get(params.caseId);
  const body = await req.json().catch(() => ({}));
  const question = body.message || '';

  const reportData = reportsStore.get(params.caseId);
  const fileNames = caseData ? caseData.files.map(f => `${f.original_filename} (${f.verdict})`).join(', ') : 'None';

  return NextResponse.json({
    role: 'assistant',
    content: `Forensic inquiry grounded in case evidence (${fileNames}): Based on static triage, no code execution occurred. Verdict: ${reportData?.report?.verdict || 'Triage in progress'}.`,
    evidence_citations: ['EVID-BASE', 'CHAIN-OF-CUSTODY']
  });
}
