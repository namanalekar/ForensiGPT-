import { NextResponse } from 'next/server';
import { reportsStore } from '@/lib/store';

export async function GET(
  req: Request,
  { params }: { params: { caseId: string } }
) {
  const data = reportsStore.get(params.caseId);
  if (!data) return NextResponse.json({ detail: 'No report found' }, { status: 404 });
  return NextResponse.json(data);
}
