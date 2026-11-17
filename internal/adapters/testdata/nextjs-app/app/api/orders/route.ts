// App Router. The path is the directory this file sits in; the methods are the
// names of the functions it exports. Neither is written down anywhere a regex
// over this file could find.
import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json([]);
}

export async function POST(request: Request) {
  const body = await request.json();
  return NextResponse.json({ ok: true, item: body.item }, { status: 201 });
}
