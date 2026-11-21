import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from app.models.db_models import get_db
from app.analyzers.exif import ExifForensicsAnalyzer

class AnchorExtractor:
    """
    Extracts candidate anchor timestamps from image metadata (EXIF DateTimeOriginal,
    ModifyDate, Digitized), filesystem attributes, and upload timestamp.
    """

    @classmethod
    def get_anchors_for_file(
        cls,
        file_path: Path,
        file_id: str,
        original_filename: str,
        uploaded_at: str,
        user_timezone_offset_hours: float = 0.0
    ) -> list[dict[str, Any]]:
        anchors = []

        # 1. Upload timestamp
        try:
            up_dt = datetime.fromisoformat(uploaded_at.replace("Z", "+00:00"))
            anchors.append({
                "anchor_type": "upload_time",
                "label": "File Ingestion / Upload Timestamp",
                "iso_timestamp": up_dt.isoformat(),
                "epoch": up_dt.timestamp(),
                "source": "Platform Chain of Custody",
                "confidence": "High"
            })
        except Exception:
            pass

        # 2. Filesystem mtime / ctime
        if file_path.exists():
            st = file_path.stat()
            mtime_dt = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
            anchors.append({
                "anchor_type": "fs_mtime",
                "label": "Filesystem Last Modification Time (mtime)",
                "iso_timestamp": mtime_dt.isoformat(),
                "epoch": mtime_dt.timestamp(),
                "source": "Filesystem Metadata",
                "confidence": "Medium"
            })

        # 3. EXIF metadata
        exif_res = ExifForensicsAnalyzer.analyze(file_path, original_filename)
        meta = exif_res.get("metadata", {})

        def parse_exif_ts(ts_str: str, label: str, anchor_type: str):
            if not ts_str:
                return
            for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt_naive = datetime.strptime(ts_str, fmt)
                    # Apply user offset if OffsetTimeOriginal not present
                    offset_hours = user_timezone_offset_hours
                    if meta.get("offset_time_original"):
                        m_off = re.match(r'([+-])(\d{2}):(\d{2})', meta["offset_time_original"])
                        if m_off:
                            sign, hh, mm = m_off.groups()
                            offset_hours = (int(hh) + int(mm) / 60.0) * (1 if sign == "+" else -1)

                    epoch = dt_naive.replace(tzinfo=timezone.utc).timestamp() - (offset_hours * 3600)
                    dt_iso = datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
                    anchors.append({
                        "anchor_type": anchor_type,
                        "label": label,
                        "iso_timestamp": dt_iso,
                        "epoch": epoch,
                        "source": f"EXIF ({ts_str})",
                        "offset_applied_hours": offset_hours,
                        "confidence": "High" if anchor_type == "exif_datetime_original" else "Medium"
                    })
                    break
                except ValueError:
                    pass

        parse_exif_ts(meta.get("date_time_original"), "EXIF Original Capture Time (DateTimeOriginal)", "exif_datetime_original")
        parse_exif_ts(meta.get("date_time_modify"), "EXIF Modification Time (ModifyDate)", "exif_datetime_modify")
        parse_exif_ts(meta.get("date_time_digitized"), "EXIF Digitization Time (DateTimeDigitized)", "exif_datetime_digitized")

        return anchors
