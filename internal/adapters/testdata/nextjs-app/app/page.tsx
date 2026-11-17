// A page, not an endpoint. The surface is what the checks probe for broken
// access control and injection, and a rendered page is neither -- including it
// would pad the route list with things no check can act on.
export default function Home() {
  return null;
}
