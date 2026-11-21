import { NextResponse } from 'next/server';

export async function GET() {
  const apiKey = process.env.GEMINI_API_KEY || '';
  return NextResponse.json({
    gemini_model: process.env.GEMINI_MODEL || 'gemini-3.5-flash',
    gemini_api_key_set: apiKey.length > 0,
    privacy_mode_default: false,
    retention_hours: 24,
    max_upload_size_mb: 25,
    virustotal_configured: !!process.env.VIRUSTOTAL_API_KEY
  });
}
