// A dynamic segment in the Pages Router is the filename rather than the
// directory.
import type { NextApiRequest, NextApiResponse } from 'next';

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  return res.status(200).json({ id: req.query.id });
}
