import { NextResponse } from 'next/server';
import { casesStore, reportsStore } from '@/lib/store';

export async function POST() {
  casesStore.clear();
  reportsStore.clear();
  return NextResponse.json({ message: 'All cases and forensic data purged successfully' });
}
