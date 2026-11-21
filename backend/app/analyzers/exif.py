import re
import math
import io
from pathlib import Path
from datetime import datetime
from typing import Any
from PIL import Image, ExifTags
import exifread
from app.models.pydantic_models import EvidenceItem

EDITING_SOFTWARE_KEYWORDS = [
    "photoshop", "gimp", "canva", "lightroom", "exiftool", "paint.net",
    "photopea", "pixelmator", "snapseed", "affinity", "coreldraw", "vsco"
]

CAMERA_FILENAME_PATTERNS = [
    r'^IMG_\d+\.(jpg|jpeg|heic)$',
    r'^DSC_?\d+\.(jpg|jpeg)$',
    r'^PANO_\d+\.(jpg|jpeg)$',
    r'^DCIM_\d+\.(jpg|jpeg)$',
    r'^\d{8}_\d{6}\.(jpg|jpeg)$',  # Android camera naming: 20261121_120000.jpg
]

def _convert_to_degrees(value) -> float:
    """Helper function to convert GPS coordinates stored in EXIF to decimal degrees."""
    d = float(value.values[0].num) / float(value.values[0].den)
    m = float(value.values[1].num) / float(value.values[1].den)
    s = float(value.values[2].num) / float(value.values[2].den)
    return d + (m / 60.0) + (s / 3600.0)

class ExifForensicsAnalyzer:
    """
    Forensic EXIF/Metadata analyzer.
    Extracts camera metadata, timestamps, GPS, and thumbnails,
    and identifies inconsistencies and tampering indicators.
    """

    @classmethod
    def analyze(cls, file_path: Path, original_filename: str) -> dict[str, Any]:
        evidence_items: list[EvidenceItem] = []
        metadata_dict: dict[str, Any] = {}
        anomalies: list[str] = []

        # Read using exifread
        exif_tags = {}
        try:
            with open(file_path, "rb") as f:
                exif_tags = exifread.process_file(f, details=True)
        except Exception:
            pass

        # Also inspect using Pillow
        pillow_exif = {}
        image_dims = (0, 0)
        has_thumbnail = False
        thumbnail_bytes = None

        try:
            with Image.open(file_path) as img:
                image_dims = (img.width, img.height)
                raw_exif = img.getexif()
                if raw_exif:
                    for k, v in raw_exif.items():
                        tag_name = ExifTags.TAGS.get(k, str(k))
                        pillow_exif[tag_name] = str(v)
        except Exception:
            pass

        # Normalize metadata fields
        make = str(exif_tags.get("Image Make") or pillow_exif.get("Make") or "").strip()
        model = str(exif_tags.get("Image Model") or pillow_exif.get("Model") or "").strip()
        software = str(exif_tags.get("Image Software") or pillow_exif.get("Software") or "").strip()
        date_original = str(exif_tags.get("EXIF DateTimeOriginal") or pillow_exif.get("DateTimeOriginal") or "").strip()
        date_modify = str(exif_tags.get("Image DateTime") or pillow_exif.get("DateTime") or "").strip()
        date_digitized = str(exif_tags.get("EXIF DateTimeDigitized") or pillow_exif.get("DateTimeDigitized") or "").strip()
        offset_time = str(exif_tags.get("EXIF OffsetTimeOriginal") or pillow_exif.get("OffsetTimeOriginal") or "").strip()
        user_comment = str(exif_tags.get("EXIF UserComment") or pillow_exif.get("UserComment") or "").strip()

        # Parse GPS
        gps_lat = None
        gps_lon = None
        try:
            if "GPS GPSLatitude" in exif_tags and "GPS GPSLatitudeRef" in exif_tags:
                lat = _convert_to_degrees(exif_tags["GPS GPSLatitude"])
                if exif_tags["GPS GPSLatitudeRef"].values[0] != "N":
                    lat = -lat
                gps_lat = round(lat, 6)

            if "GPS GPSLongitude" in exif_tags and "GPS GPSLongitudeRef" in exif_tags:
                lon = _convert_to_degrees(exif_tags["GPS GPSLongitude"])
                if exif_tags["GPS GPSLongitudeRef"].values[0] != "E":
                    lon = -lon
                gps_lon = round(lon, 6)
        except Exception:
            pass

        metadata_dict = {
            "make": make,
            "model": model,
            "software": software,
            "date_time_original": date_original,
            "date_time_modify": date_modify,
            "date_time_digitized": date_digitized,
            "offset_time_original": offset_time,
            "user_comment": user_comment,
            "gps_latitude": gps_lat,
            "gps_longitude": gps_lon,
            "image_dimensions": f"{image_dims[0]}x{image_dims[1]}",
            "has_exif": bool(exif_tags or pillow_exif)
        }

        # Check 1: Editing software traces
        combined_software = f"{software} {user_comment}".lower()
        matched_editors = [ed for ed in EDITING_SOFTWARE_KEYWORDS if ed in combined_software]
        if matched_editors:
            desc = f"Image metadata contains traces of editing software: {', '.join(matched_editors)} (Software: '{software}')."
            anomalies.append(desc)
            evidence_items.append(EvidenceItem(
                evidence_id="EVID-IMG-EXIF-001",
                severity="Medium",
                category="Image Tampering Indicator",
                title="Editing Software Traces Detected",
                description=desc,
                raw_data={"matched_editors": matched_editors, "software_tag": software}
            ))

        # Check 2: Timestamp Inconsistencies
        dt_orig = None
        dt_mod = None
        for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            if date_original and not dt_orig:
                try:
                    dt_orig = datetime.strptime(date_original, fmt)
                except ValueError:
                    pass
            if date_modify and not dt_mod:
                try:
                    dt_mod = datetime.strptime(date_modify, fmt)
                except ValueError:
                    pass

        if dt_orig and dt_mod:
            if dt_orig > dt_mod:
                desc = (
                    f"Timestamp Conflict: DateTimeOriginal ({date_original}) is later than ModifyDate ({date_modify}). "
                    "This indicates metadata manipulation or clock desynchronization."
                )
                anomalies.append(desc)
                evidence_items.append(EvidenceItem(
                    evidence_id="EVID-IMG-EXIF-002",
                    severity="High",
                    category="Timestamp Inconsistency",
                    title="DateTimeOriginal Later Than ModifyDate",
                    description=desc,
                    raw_data={"date_original": date_original, "date_modify": date_modify}
                ))

        # Check future timestamp
        now = datetime.now()
        if dt_orig and dt_orig.year > (now.year + 1):
            desc = f"Anomalous Future Timestamp: DateTimeOriginal ({date_original}) is set in the future."
            anomalies.append(desc)
            evidence_items.append(EvidenceItem(
                evidence_id="EVID-IMG-EXIF-003",
                severity="High",
                category="Timestamp Inconsistency",
                title="Future Timestamp Detected",
                description=desc,
                raw_data={"date_original": date_original}
            ))

        # Check 3: Impossible GPS Coordinates
        if gps_lat is not None and (gps_lat < -90 or gps_lat > 90):
            desc = f"Impossible GPS Latitude: {gps_lat}° (valid range is -90° to +90°)."
            anomalies.append(desc)
            evidence_items.append(EvidenceItem(
                evidence_id="EVID-IMG-EXIF-004",
                severity="High",
                category="Geographic Inconsistency",
                title="Impossible GPS Coordinates",
                description=desc,
                raw_data={"latitude": gps_lat, "longitude": gps_lon}
            ))
        if gps_lon is not None and (gps_lon < -180 or gps_lon > 180):
            desc = f"Impossible GPS Longitude: {gps_lon}° (valid range is -180° to +180°)."
            anomalies.append(desc)
            evidence_items.append(EvidenceItem(
                evidence_id="EVID-IMG-EXIF-004",
                severity="High",
                category="Geographic Inconsistency",
                title="Impossible GPS Coordinates",
                description=desc,
                raw_data={"latitude": gps_lat, "longitude": gps_lon}
            ))

        # Check 4: Missing EXIF on Camera Original Filenames
        is_camera_file = any(re.match(pat, original_filename, re.IGNORECASE) for pat in CAMERA_FILENAME_PATTERNS)
        if is_camera_file and not bool(exif_tags or pillow_exif):
            desc = (
                f"Filename '{original_filename}' adheres to standard camera naming conventions, "
                "but all EXIF/camera metadata is missing. The metadata was likely stripped."
            )
            anomalies.append(desc)
            evidence_items.append(EvidenceItem(
                evidence_id="EVID-IMG-EXIF-005",
                severity="Low",
                category="Metadata Anomaly",
                title="Missing EXIF on Purported Camera Original",
                description=desc,
                raw_data={"filename": original_filename}
            ))

        # Check 5: Thumbnail Inconsistency Detection
        thumbnail_mismatch_detected = False
        if "JPEGThumbnail" in exif_tags:
            has_thumbnail = True
            thumb_data = exif_tags["JPEGThumbnail"]
            try:
                thumb_img = Image.open(io.BytesIO(thumb_data)).convert("RGB")
                with Image.open(file_path) as full_img:
                    main_downsampled = full_img.convert("RGB").resize(thumb_img.size)

                    # Compute Mean Squared Error between downsampled main and embedded thumbnail
                    import numpy as np
                    arr_thumb = np.array(thumb_img, dtype=np.float32)
                    arr_main = np.array(main_downsampled, dtype=np.float32)
                    mse = float(np.mean((arr_thumb - arr_main) ** 2))

                    # High MSE indicates thumbnail depicts different content (cropped / replaced)
                    if mse > 5000.0:  # Substantial visual divergence
                        thumbnail_mismatch_detected = True
                        desc = (
                            f"Thumbnail Discrepancy: Embedded EXIF thumbnail significantly diverges from the main image "
                            f"(MSE: {mse:.1f}). This commonly indicates the main image was edited or cropped while the "
                            "embedded thumbnail was left unaltered."
                        )
                        anomalies.append(desc)
                        evidence_items.append(EvidenceItem(
                            evidence_id="EVID-IMG-EXIF-006",
                            severity="High",
                            category="Image Tampering Indicator",
                            title="Embedded Thumbnail Diverges From Main Image",
                            description=desc,
                            raw_data={"mse": round(mse, 2), "thumb_dimensions": f"{thumb_img.width}x{thumb_img.height}"}
                        ))
            except Exception:
                pass

        metadata_dict["has_thumbnail"] = has_thumbnail
        metadata_dict["thumbnail_mismatch"] = thumbnail_mismatch_detected
        metadata_dict["anomalies_detected"] = len(anomalies)

        return {
            "metadata": metadata_dict,
            "evidence_items": [e.model_dump() for e in evidence_items],
            "anomalies": anomalies
        }
