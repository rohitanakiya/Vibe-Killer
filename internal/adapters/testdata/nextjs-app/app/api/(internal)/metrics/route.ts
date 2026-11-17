// A route group. Parenthesised directories organise files and contribute
// nothing to the URL, so this is served at /api/metrics -- reporting it at
// /api/(internal)/metrics would be a path nothing answers.
import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json({ ok: true });
}
