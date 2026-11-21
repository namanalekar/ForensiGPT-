import os
from PIL import Image

out_dir = r"C:\Users\naman\.gemini\antigravity\scratch\forensigpt\samples"
os.makedirs(out_dir, exist_ok=True)

# 1. Suspicious file with extension mismatch and trailing data (Claimed .jpg, actually ZIP with hidden trailing script)
zip_header = b"PK\x03\x04\x14\x00\x00\x00\x08\x00" + b"A"*100 + b"\x50\x4b\x05\x06" + b"\x00"*18 + b"EXTRA_MALICIOUS_PAYLOAD_AFTER_EOF"
with open(os.path.join(out_dir, "suspicious_payload.jpg"), "wb") as f:
    f.write(zip_header)

# 2. Surveillance image with EXIF timestamp
img = Image.new("RGB", (250, 250), color=(24, 48, 89))
for x in range(50, 200):
    for y in range(50, 200):
        img.putpixel((x, y), ((x*3)%256, (y*5)%256, 160))

exif = img.getexif()
# DateTimeOriginal (0x9003), Software (0x0131), Make (0x010F), Model (0x0110)
exif[0x9003] = "2026:11:20 14:30:15"
exif[0x0131] = "Adobe Photoshop 2026"
exif[0x010F] = "Canon"
exif[0x0110] = "EOS 5D Mark IV"
img.save(os.path.join(out_dir, "surveillance_capture.jpg"), "JPEG", exif=exif)

# 3. Server auth log with brute force and privilege escalation correlated with image
auth_lines = [
    "Nov 20 14:28:10 web-gateway sshd[10412]: Failed password for invalid user admin from 203.0.113.5 port 44321 ssh2\n",
    "Nov 20 14:28:15 web-gateway sshd[10415]: Failed password for invalid user admin from 203.0.113.5 port 44322 ssh2\n",
    "Nov 20 14:28:22 web-gateway sshd[10420]: Failed password for root from 203.0.113.5 port 44325 ssh2\n",
    "Nov 20 14:28:30 web-gateway sshd[10425]: Failed password for root from 203.0.113.5 port 44328 ssh2\n",
    "Nov 20 14:29:34 web-gateway sshd[10450]: Accepted password for deploy from 203.0.113.5 port 44330 ssh2\n",
    "Nov 20 14:29:45 web-gateway sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash\n",
    "Nov 20 14:30:00 web-gateway useradd[10490]: new user: name=backdoor_user, UID=1002, GID=1002, home=/home/backdoor_user\n",
    "Nov 20 14:30:15 web-gateway sshd[10500]: Received disconnect from 203.0.113.5 port 44330:11: disconnected by user\n",
    "Nov 20 14:31:02 web-gateway systemd[1]: Started Security Audit Logging Daemon.\n",
]
with open(os.path.join(out_dir, "auth.log"), "w") as f:
    f.writelines(auth_lines)

print("Sample files generated successfully.")
