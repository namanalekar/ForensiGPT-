import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json({
    protocols: [
      {
        title: 'Zero Execution Policy',
        guideline: 'Never double-click or run unverified binaries, shortcuts, or scripts on your host operating system.'
      },
      {
        title: 'Isolated Virtual Sandboxing',
        guideline: 'Inspect suspicious executables, archives, and macro-enabled documents only inside an air-gapped VM.'
      },
      {
        title: 'Cryptographic Chain of Custody',
        guideline: 'Always verify SHA-256 and MD5 hashes before and after transmitting evidentiary files.'
      }
    ]
  });
}
