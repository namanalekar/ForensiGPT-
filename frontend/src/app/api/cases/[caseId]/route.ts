import { NextResponse } from 'next/server';
import { casesStore } from '@/lib/store';

export async function GET(
  req: Request,
  { params }: { params: { caseId: string } }
) {
  const caseData = casesStore.get(params.caseId);
  if (!caseData) {
    return NextResponse.json({ detail: 'Case not found' }, { status: 404 });
  }
  return NextResponse.json(caseData);
}

export async function DELETE(
  req: Request,
  { params }: { params: { caseId: string } }
) {
  casesStore.delete(params.caseId);
  return new NextResponse(null, { status: 204 });
}
