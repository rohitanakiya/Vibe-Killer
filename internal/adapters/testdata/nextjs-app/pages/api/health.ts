// Pages Router. Every file under pages/api is an endpoint, and the file's own
// name is the last path segment.
import type { NextApiRequest, NextApiResponse } from 'next';

export default function handler(_req: NextApiRequest, res: NextApiResponse) {
  res.status(200).json({ ok: true });
}
