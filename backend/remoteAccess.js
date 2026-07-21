import os from 'node:os';
import crypto from 'node:crypto';

// Token for non-loopback (LAN) callers. Regenerated on every start unless the
// operator pins one via KARTTEST_REMOTE_TOKEN (e.g. for a fixed pairing code).
export const REMOTE_TOKEN = process.env.KARTTEST_REMOTE_TOKEN || crypto.randomBytes(9).toString('base64url');

// Paths reachable without a token even from the LAN: /health for basic
// reachability probing, /remote/info so a genuinely local caller can look up
// the token (it self-restricts to loopback below).
const OPEN_PATHS = new Set(['/health', '/remote/info']);

export function isLoopback(req) {
  const ip = req.ip || req.socket?.remoteAddress || '';
  return ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1';
}

export function lanUrls(port) {
  const nets = os.networkInterfaces();
  const urls = [];
  for (const entries of Object.values(nets)) {
    for (const net of entries || []) {
      if (net.family === 'IPv4' && !net.internal) urls.push(`http://${net.address}:${port}`);
    }
  }
  return urls;
}

// Requests from the machine itself are always trusted (existing local
// workflow keeps working unauthenticated). Anything arriving over the
// network must present the access token — this is what turns "backend
// happens to be reachable on the LAN" into an intentional remote-control
// feature instead of an open card-command endpoint.
export function requireRemoteAuth(req, res, next) {
  if (isLoopback(req) || OPEN_PATHS.has(req.path)) return next();
  const auth = req.headers.authorization || '';
  const headerToken = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const queryToken = typeof req.query.token === 'string' ? req.query.token : '';
  const provided = headerToken || queryToken;
  if (provided && provided === REMOTE_TOKEN) return next();
  res.status(401).json({ error: "Uzaktan erişim için geçerli bir token gerekli (Authorization: Bearer <token>)" });
}
