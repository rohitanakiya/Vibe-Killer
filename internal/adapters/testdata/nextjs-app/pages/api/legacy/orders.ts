// The Pages Router does not declare its methods: one handler serves them all
// and decides by reading req.method. Where the source states which it accepts,
// that is worth reading; where it does not, assuming more than GET would hand
// the endpoint layer a mutating route nothing promised.
import type { NextApiRequest, NextApiResponse } from 'next';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method === 'POST') {
    return res.status(201).json({ ok: true });
  }
  if (req.method === 'GET') {
    return res.status(200).json([]);
  }
  return res.status(405).end();
}
