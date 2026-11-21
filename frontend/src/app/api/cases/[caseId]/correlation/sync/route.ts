import { NextResponse } from 'next/server';
import { casesStore } from '@/lib/store';

export async function POST(
  req: Request,
  { params }: { params: { caseId: string } }
) {
  const caseData = casesStore.get(params.caseId);
  if (!caseData) return NextResponse.json({ detail: 'Case not found' }, { status: 404 });

  const body = await req.json().catch(() => ({}));
  const winSec = body.window_seconds || 300;
  const offsetSec = body.manual_offset_seconds || 0;

  return NextResponse.json({
    case_id: params.caseId,
    anchor_file_id: body.anchor_file_id || '',
    anchor_epoch: body.anchor_epoch || Date.now() / 1000,
    effective_anchor_epoch: (body.anchor_epoch || Date.now() / 1000) + offsetSec,
    window_seconds: winSec,
    manual_offset_seconds: offsetSec,
    correlated_events: [],
    before_after_patterns: [],
    swimlane: {
      window_start_iso: new Date(Date.now() - winSec * 1000).toISOString(),
      window_end_iso: new Date(Date.now() + winSec * 1000).toISOString(),
      anchor: {
        file_id: body.anchor_file_id || '',
        label: body.anchor_label || 'Anchor Timestamp',
        anchor_type: body.anchor_type || 'upload_time',
        effective_iso: new Date().toISOString(),
        manual_offset_applied: offsetSec
      },
      events_track: [],
      total_in_window: 0
    }
  });
}
