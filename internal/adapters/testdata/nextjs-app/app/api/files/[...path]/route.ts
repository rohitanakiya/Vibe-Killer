// A catch-all segment, which matches any number of path components.
import { NextResponse } from 'next/server';

export async function GET(_request: Request, { params }: { params: { path: string[] } }) {
  return NextResponse.json({ path: params.path.join('/') });
}
