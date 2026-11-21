# ForensiGPT: AI-Powered Image, File & Log Forensics Investigator

[![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![React 18](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**ForensiGPT** is an open-source, production-grade Digital Forensics and Incident Response (DFIR) investigation workbench. It combines deterministic static forensic inspection (magic bytes, EXIF metadata, steganography signatures, entropy heatmaps, Error Level Analysis, LSB bitplanes, and normalized log parsing) with Google Gemini AI to synthesize transparent, evidence-grounded investigative dossiers.

> **Core Design Principle**: Deterministic tools uncover the facts; Gemini explains them. Gemini never invents findings—it only receives structured evidence JSON and cites deterministic Evidence IDs (`EVID-*`).

---

## Key Capabilities

### 1. Zero-Trust File Identification & Unverified Alerts
- **True Type Magic Byte Detection**: Bypasses spoofed file extensions using binary signatures.
- **Unverified / Miscellaneous File Modal**: Triggers immediately on unknown binaries, extension mismatches, trailing bytes post-EOF, or stripped camera metadata. Prompts explicit investigator acknowledgment with persistent `UNVERIFIED` badges.
- **Defensive Verdicts**: Ranks files as `Verified-Clean-Looking`, `Unverified`, `Suspicious`, or `Likely Malicious`.

### 2. Deep Image Forensics Engine
- **Metadata Forensics**: Full EXIF, XMP, and IPTC extraction, checking for editing software footprints (Photoshop, GIMP) and conflicting GPS/timestamp records.
- **Steganography & Carving Indicators**: Scans for appended payloads past JPEG `FFD9` or PNG `IEND`, carves embedded archives (ZIP, RAR, 7Z, ELF, PE, PDF), and performs pure-math $\chi^2$ and LSB bitplane analysis.
- **Visual Forensic Artifacts**:
  - **Error Level Analysis (ELA)**: Visualizes JPEG recompression compression artifacts.
  - **2D Entropy Heatmap**: 8x8 block Shannon entropy rasterization.
  - **LSB Bitplane Viewer**: Isolates least significant pixel bitplanes.

### 3. Log Forensics Engine & MITRE ATT&CK
- **Multi-Format Ingestion**: Normalizes Linux `auth.log`, `syslog`, and web access logs (Nginx/Apache).
- **Incident Heuristics**: Automatically flags SSH brute-force bursts, unauthorized `sudo`/`su` privilege escalations, new user creation, and service tampering.
- **IOC Defanging & MITRE Tagging**: Automatically defangs indicators (`hxxp://`, `192[.]168[.]1[.]1`) and maps detections to MITRE ATT&CK techniques (`T1110.001`, `T1548.003`, `T1059.004`, `T1105`, etc.).

### 4. Image-to-Log Synchronization (Swimlane Correlation)
- **Multi-Source Anchor Timestamps**: Correlates file creation, modification, or EXIF timestamps against server log events.
- **Interactive Visual Swimlane**: Inspect events inside an adjustable correlation window ($\pm 30$ seconds to $2$ hours).
- **Clock-Skew Adjustment**: Detects timestamp desynchronization and provides a live manual offset slider.
- **Before/After Pattern Deltas**: Identifies tactical temporal relations (e.g., *"SSH login from 203.0.113.5 occurred 41 seconds before image modification"*).

### 5. Gemini-Powered Forensic Dossiers
- **Structured Pydantic Validation**: Generates executive summaries, chain-of-custody tables, risk score breakdowns, key findings with evidence citations, and recommended next steps.
- **Multi-Tier Explanations**: Toggle between **ELI5 (Beginner)**, **Analyst**, and **Technical/Expert** perspectives.
- **"Ask the Evidence" Grounded Chat**: An interactive chat drawer grounded exclusively in deterministic evidence JSON.
- **Multi-Format Exports**: Export to PDF, Markdown, JSON, and CSV timeline formats.

### 6. Security & Anti-Prompt-Injection Safeguards
- **In-Memory Injection Guard**: Detects adversarial directives hidden in metadata or logs (`EVID-INJ-001`).
- **Privacy Mode**: One-click local-only offline analysis with zero cloud egress.
- **Pre-Flight Redaction**: Review and redact sensitive IP addresses, usernames, and coordinates prior to LLM transmission.
- **Automated Lifecycle**: 24-hour default retention window with an instant manual purge button.

---

## Architecture

```
forensigpt/
├── backend/
│   ├── app/
│   │   ├── ai/            # Gemini client, prompt templates, anti-injection guard
│   │   ├── analyzers/     # Magic bytes, EXIF, stego, entropy, ELA, LSB, logs, IOCs
│   │   ├── api/           # FastAPI REST endpoints
│   │   ├── core/          # Security sanitization, rate limiter, config, cleanup
│   │   ├── correlation/   # Timestamp anchor extraction & swimlane correlation
│   │   ├── models/        # SQLite schema & Pydantic v2 data models
│   │   ├── reports/       # ReportLab PDF, Markdown, JSON export generators
│   │   └── main.py        # ASGI application entrypoint
│   └── tests/             # Pytest test suite (100% pass)
├── frontend/
│   ├── src/
│   │   ├── components/    # Dark security-console UI components
│   │   ├── services/      # Axios API client
│   │   ├── types/         # TypeScript DFIR definitions
│   │   ├── App.tsx        # Investigation workbench controller
│   │   └── main.tsx       # React 18 entrypoint
│   └── index.html
├── Dockerfile.backend
├── Dockerfile.frontend
├── docker-compose.yml
└── .env.example
```

---

## Quick Start

### Option A: Docker Compose (Recommended)

1. Clone the repository and configure your environment:
   ```bash
   cp .env.example .env
   # Edit .env and supply your GEMINI_API_KEY
   ```
2. Start the services:
   ```bash
   docker-compose up --build
   ```
3. Open your browser at `http://localhost:3000`.

---

### Option B: Local Development

#### 1. Backend Setup
```bash
cd backend
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

#### 2. Frontend Setup
```bash
cd frontend
npm install

# Run with Vite (Fast dev server on port 5173):
npm run dev

# Or run with Next.js (App Router on port 3000):
npm run dev:next
```
Access the UI at `http://localhost:5173` (Vite) or `http://localhost:3000` (Next.js).

---

## Security Disclaimer

> **IMPORTANT**: No static forensic analysis can guarantee a file is free of malicious intent. ForensiGPT provides evidentiary indicators and contextual synthesis. Suspicious artifacts should always be quarantined and inspected inside an isolated sandbox or analysis virtual machine.
