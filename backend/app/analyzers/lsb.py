from pathlib import Path
from typing import Any
from PIL import Image
import numpy as np
from app.core.config import settings

class LSBVisualizer:
    """
    LSB Bitplane Visualizer.
    Generates high-contrast visual representations of the Least Significant Bit (LSB)
    planes across RGB channels to expose visual patterns of hidden steganography.
    """

    @classmethod
    def generate_lsb_planes(cls, file_path: Path, file_id: str) -> dict[str, Any]:
        dest_filename = f"{file_id}_lsb_plane.png"
        dest_path = settings.VISUALS_DIR / dest_filename
        settings.VISUALS_DIR.mkdir(parents=True, exist_ok=True)

        try:
            with Image.open(file_path) as img:
                rgb_img = img.convert("RGB")
                arr = np.array(rgb_img, dtype=np.uint8)

                # Extract lowest bit of each channel and scale (0 -> 0, 1 -> 255)
                lsb_arr = (arr & 1) * 255

                lsb_img = Image.fromarray(lsb_arr, mode="RGB")
                lsb_img.save(dest_path, "PNG")

                return {
                    "lsb_artifact_path": f"/api/cases/visuals/{dest_filename}",
                    "width": rgb_img.width,
                    "height": rgb_img.height,
                    "description": "Visual representation of the Least Significant Bit plane across Red, Green, and Blue channels."
                }
        except Exception as e:
            return {
                "lsb_artifact_path": None,
                "error": f"Failed to generate LSB visualizer: {str(e)}"
            }
