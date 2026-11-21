import type { Metadata } from 'next';
import '../index.css';

export const metadata: Metadata = {
  title: 'ForensiGPT — AI-Powered Digital Forensics Investigator',
  description: 'Deterministic digital forensics meets Google Gemini AI',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡</text></svg>" />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet" />
      </head>
      <body className="bg-[#090D16] text-slate-100 min-h-screen selection:bg-cyan-500 selection:text-black">
        {children}
      </body>
    </html>
  );
}
