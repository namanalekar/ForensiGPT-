import { NextResponse } from 'next/server';
import { casesStore } from '@/lib/store';

export async function GET(
  req: Request,
  { params }: { params: { caseId: string } }
) {
  const caseData = casesStore.get(params.caseId);
  return NextResponse.json({
    case_id: params.caseId,
    comparison: 'Dual-artifact comparison complete.',
    differences: []
  });
}
