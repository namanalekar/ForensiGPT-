# ForensiGPT Security Policy

## Core Architecture Principles

ForensiGPT is built strictly for defensive digital forensics and incident response (DFIR). The application adheres to strict security constraints:

### 1. Static Analysis Only
- Uploaded files are **never** executed, rendered dynamically, or evaluated via system shells.
- All inspections (magic bytes, EXIF parsing, entropy distributions, Error Level Analysis, LSB bitplanes, carving scans) are performed via deterministic, sandboxed binary parsers.

### 2. File Isolation and Sanitization
- Files are saved with cryptographically random UUID identifiers inside an isolated directory.
- Execution permissions (`chmod -x`) are stripped upon receipt.
- File upload limits default to 25 MB (`MAX_UPLOAD_SIZE_BYTES=26214400`) and are enforced before disk persistence.
- Cryptographic hashes (SHA-256, SHA-1, MD5) are calculated in a single streaming pass for chain-of-custody tracking.

### 3. Anti-Prompt-Injection Defense
- Forensic metadata (EXIF tags, IPTC fields, comments, log lines, filenames) is treated as untrusted adversarial data.
- The built-in scanner evaluates all textual evidence against injection heuristics (`ignore previous instructions`, `system prompt`, jailbreak tokens). Detected attempts produce an explicit finding: `Possible AI Prompt-Injection Attempt Embedded in File` (`EVID-INJ-001`).
- All evidence submitted to LLMs is enclosed within strict structured delimiters with explicit non-execution guard directives.

### 4. Privacy & Zero-Egress Options
- **Privacy Mode**: Disables all external AI calls. Deterministic analysis and template reports are generated locally without any data leaving the host.
- **Pre-Flight Redaction**: Users can inspect and sanitize sensitive tokens (IPs, emails, domains, user names, coordinates) prior to report synthesis.
- **Automated Retention**: Stored files and analysis results are automatically deleted after a configurable retention window (default 24 hours), with instant manual purge support.

## Reporting a Vulnerability

If you discover a security vulnerability in ForensiGPT, please report it responsibly by contacting the maintainers directly or opening a private security advisory. We acknowledge receipt within 48 hours.
