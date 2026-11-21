import json
from datetime import datetime, timezone
from typing import Any
from app.models.db_models import get_db

class ImageLogSyncEngine:
    """
    Image-to-Log Synchronization & Correlation Engine.
    Correlates image/file anchor timestamps with host and network log events within a
    temporal window, detects clock skew, ranks forensic relevance, and computes before/after deltas.
    """

    @classmethod
    def correlate(
        cls,
        case_id: str,
        anchor_file_id: str,
        anchor_epoch: float,
        anchor_type: str,
        anchor_label: str,
        window_seconds: int = 300,
        manual_offset_seconds: int = 0
    ) -> dict[str, Any]:
        effective_anchor_epoch = anchor_epoch + manual_offset_seconds
        t_start = effective_anchor_epoch - window_seconds
        t_end = effective_anchor_epoch + window_seconds

        with get_db() as db:
            # Query log events for this case
            cursor = db.execute(
                """
                SELECT id, file_id, timestamp, timestamp_epoch, host, process,
                       message, line_number, raw_line, normalized_type, relevance_score,
                       iocs, mitre_tags
                FROM log_events
                WHERE case_id = ? AND timestamp_epoch > 0
                ORDER BY timestamp_epoch ASC
                """,
                (case_id,)
            )
            all_log_events = [dict(row) for row in cursor.fetchall()]

        if not all_log_events:
            return {
                "case_id": case_id,
                "anchor_file_id": anchor_file_id,
                "anchor_epoch": anchor_epoch,
                "manual_offset_seconds": manual_offset_seconds,
                "window_seconds": window_seconds,
                "clock_skew_warning": "No timestamped log events found in this case to correlate.",
                "correlated_events": [],
                "before_after_patterns": [],
                "swimlane": {}
            }

        min_log_epoch = all_log_events[0]["timestamp_epoch"]
        max_log_epoch = all_log_events[-1]["timestamp_epoch"]

        # 1. Clock Skew Detection
        clock_skew_warning = None
        has_overlap = not (t_end < min_log_epoch or t_start > max_log_epoch)

        if not has_overlap:
            # Anchor is completely outside log boundaries
            delta_days = round(abs(effective_anchor_epoch - min_log_epoch) / 86400.0, 1)
            clock_skew_warning = (
                f"Timestamps don't overlap with the logs. Possible clock skew, wrong timezone, or forged metadata. "
                f"(Anchor is ~{delta_days} days separated from log range)."
            )

        # 2. Extract In-Window Events
        in_window_events = []
        before_after_patterns = []

        for ev in all_log_events:
            ev_epoch = ev["timestamp_epoch"]
            if t_start <= ev_epoch <= t_end:
                delta = round(ev_epoch - effective_anchor_epoch, 1)
                ev_copy = dict(ev)
                ev_copy["delta_seconds"] = delta
                ev_copy["iocs"] = json.loads(ev["iocs"] or "[]")
                ev_copy["mitre_tags"] = json.loads(ev["mitre_tags"] or "[]")

                # Pattern description
                if delta < 0:
                    delta_desc = f"{abs(delta):.1f}s BEFORE file anchor"
                elif delta > 0:
                    delta_desc = f"{delta:.1f}s AFTER file anchor"
                else:
                    delta_desc = "COINCIDENT with file anchor (0.0s)"

                ev_copy["delta_desc"] = delta_desc
                in_window_events.append(ev_copy)

                # Flag high-relevance before/after patterns
                if ev["relevance_score"] >= 60:
                    pattern_text = f"[{ev['normalized_type'].upper()}] {ev['process']} event occurred {delta_desc}: {ev['message']}"
                    before_after_patterns.append({
                        "event_id": ev["id"],
                        "delta_seconds": delta,
                        "description": pattern_text,
                        "relevance": ev["relevance_score"]
                    })

        # Sort in-window events by forensic relevance then by time
        in_window_events.sort(key=lambda x: (-x["relevance_score"], abs(x["delta_seconds"])))

        # 3. Swimlane Timeline Builder
        eff_iso = datetime.fromtimestamp(effective_anchor_epoch, tz=timezone.utc).isoformat()
        swimlane = {
            "window_start_iso": datetime.fromtimestamp(t_start, tz=timezone.utc).isoformat(),
            "window_end_iso": datetime.fromtimestamp(t_end, tz=timezone.utc).isoformat(),
            "anchor": {
                "file_id": anchor_file_id,
                "label": anchor_label,
                "anchor_type": anchor_type,
                "original_epoch": anchor_epoch,
                "effective_epoch": effective_anchor_epoch,
                "effective_iso": eff_iso,
                "manual_offset_applied": manual_offset_seconds
            },
            "events_track": sorted(in_window_events, key=lambda x: x["timestamp_epoch"]),
            "total_in_window": len(in_window_events),
            "log_range": {
                "min_iso": datetime.fromtimestamp(min_log_epoch, tz=timezone.utc).isoformat(),
                "max_iso": datetime.fromtimestamp(max_log_epoch, tz=timezone.utc).isoformat()
            }
        }

        return {
            "case_id": case_id,
            "anchor_file_id": anchor_file_id,
            "anchor_epoch": anchor_epoch,
            "effective_anchor_epoch": effective_anchor_epoch,
            "window_seconds": window_seconds,
            "manual_offset_seconds": manual_offset_seconds,
            "clock_skew_warning": clock_skew_warning,
            "correlated_events": in_window_events,
            "before_after_patterns": before_after_patterns,
            "swimlane": swimlane
        }
