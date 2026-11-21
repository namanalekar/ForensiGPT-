import { NextResponse } from 'next/server';
import crypto from 'crypto';
import { casesStore } from '@/lib/store';

export async function GET() {
  const cases = Array.from(casesStore.values()).sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  );
  return NextResponse.json(cases);
}

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({}));
    const title = body.title || `Incident Case ${Date.now().toString().slice(-4)}`;
    const description = body.description || '';
    const id = crypto.randomUUID();
    const newCase = {
      id,
      title,
      description,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      status: 'open',
      files: []
    };
    casesStore.set(id, newCase);
    return NextResponse.json(newCase);
  } catch (err: any) {
    return NextResponse.json({ detail: err.message }, { status: 500 });
  }
}
