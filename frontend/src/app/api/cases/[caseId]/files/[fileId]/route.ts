import { NextResponse } from 'next/server';
import { casesStore } from '@/lib/store';

export async function DELETE(
  req: Request,
  { params }: { params: { caseId: string; fileId: string } }
) {
  const caseData = casesStore.get(params.caseId);
  if (!caseData) {
    return NextResponse.json({ detail: 'Case not found' }, { status: 404 });
  }
  caseData.files = caseData.files.filter(f => f.id !== params.fileId);
  caseData.updated_at = new Date().toISOString();
  return new NextResponse(null, { status: 204 });
}
