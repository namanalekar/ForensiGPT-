'use client';

import dynamic from 'next/dynamic';

// Dynamically import the main forensics workbench client component to prevent SSR window mismatches
const App = dynamic(() => import('../App'), { ssr: false });

export default function Home() {
  return <App />;
}
