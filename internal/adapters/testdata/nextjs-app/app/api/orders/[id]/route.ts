// A dynamic segment. [id] is the directory name, and it is the parameter.
import { NextResponse } from 'next/server';

export async function GET(_request: Request, { params }: { params: { id: string } }) {
  return NextResponse.json({ id: params.id });
}

export async function PATCH(_request: Request, { params }: { params: { id: string } }) {
  return NextResponse.json({ id: params.id, updated: true });
}

export async function DELETE(_request: Request, { params }: { params: { id: string } }) {
  return NextResponse.json({ id: params.id, deleted: true });
}
