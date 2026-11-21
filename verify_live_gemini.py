import urllib.request
import json

req = urllib.request.Request(
    "http://127.0.0.1:8000/api/cases/2b3771b6-a49a-4e21-9e3f-3a2103debc1c/reports/generate",
    data=json.dumps({"case_id": "2b3771b6-a49a-4e21-9e3f-3a2103debc1c", "explanation_mode": "analyst", "privacy_mode": False}).encode(),
    headers={"Content-Type": "application/json"},
    method="POST"
)
try:
    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode())
        print("SUCCESS! Model used:", data.get("model_used"))
        print("Executive summary:", data["report"]["executive_summary"])
except Exception as e:
    print("Error:", e)
    if hasattr(e, "read"):
        print("Detail:", e.read().decode())
