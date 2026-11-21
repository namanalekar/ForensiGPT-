import re
from typing import Any

# Regex patterns for IOC extraction
IPV4_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
IPV6_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
URL_PATTERN = re.compile(r'https?://[^\s<>"]+|ftp://[^\s<>"]+')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|io|mil|biz|info|mobi|xyz|top|cc|ru|cn|co|uk)\b', re.IGNORECASE)
MD5_PATTERN = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_PATTERN = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_PATTERN = re.compile(r'\b[a-fA-F0-9]{64}\b')
UNIX_PATH_PATTERN = re.compile(r'(?:/(?:tmp|var|bin|usr|etc|opt|home|dev|root)/[a-zA-Z0-9_\-\./]+)')
WIN_PATH_PATTERN = re.compile(r'[a-zA-Z]:\\(?:[a-zA-Z0-9_\-\.\s]+\\)*[a-zA-Z0-9_\-\.]+')

def defang_ioc(ioc: str, ioc_type: str) -> str:
    """
    Defangs an IOC so it is safe to display in security consoles without trigger clicks:
    - http:// -> hxxp://
    - https:// -> hxxps://
    - 1.2.3.4 -> 1[.]2[.]3[.]4
    - domain.com -> domain[.]com
    """
    if not ioc:
        return ""
    if ioc_type == "url":
        defanged = ioc.replace("http://", "hxxp://").replace("https://", "hxxps://").replace("ftp://", "fxp://")
        return defanged.replace(".", "[.]")
    elif ioc_type in {"ipv4", "domain"}:
        return ioc.replace(".", "[.]")
    return ioc

class IOCExtractor:
    """
    Forensic Indicator of Compromise (IOC) Extractor.
    Extracts network, host, and cryptographic indicators from unstructured text
    and formats them with defanged representations.
    """

    @classmethod
    def extract_from_text(cls, text: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        seen = set()

        def add_ioc(val: str, ioc_type: str):
            key = (val.lower(), ioc_type)
            if key not in seen:
                seen.add(key)
                results.append({
                    "type": ioc_type,
                    "value": val,
                    "defanged": defang_ioc(val, ioc_type)
                })

        # 1. URLs
        for url in URL_PATTERN.findall(text):
            add_ioc(url, "url")

        # 2. IPv4 (filter out standard broadcast / local loops)
        for ip in IPV4_PATTERN.findall(text):
            if ip not in {"0.0.0.0", "255.255.255.255"}:
                add_ioc(ip, "ipv4")

        # 3. IPv6
        for ip6 in IPV6_PATTERN.findall(text):
            add_ioc(ip6, "ipv6")

        # 4. Domains (avoid matching plain IPs or file extensions)
        for dom in DOMAIN_PATTERN.findall(text):
            if not IPV4_PATTERN.match(dom):
                add_ioc(dom.lower(), "domain")

        # 5. Hashes
        for s256 in SHA256_PATTERN.findall(text):
            add_ioc(s256.lower(), "sha256")
        for s1 in SHA1_PATTERN.findall(text):
            add_ioc(s1.lower(), "sha1")
        for m5 in MD5_PATTERN.findall(text):
            add_ioc(m5.lower(), "md5")

        # 6. File Paths
        for p in UNIX_PATH_PATTERN.findall(text):
            add_ioc(p, "path")
        for p in WIN_PATH_PATTERN.findall(text):
            add_ioc(p, "path")

        return results
