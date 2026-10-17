// Container health check (deploy/Dockerfile HEALTHCHECK). Asks the server on
// its own loopback port; healthy only when /api/health says ok and the
// database answered. Exit 0 = healthy, 1 = unhealthy.
const port = process.env.PORT ?? '3000';

try {
  const res = await fetch(`http://127.0.0.1:${port}/api/health`, { signal: AbortSignal.timeout(4000) });
  const body = await res.json();
  process.exit(res.ok && body.ok === true && body.db === 'ok' ? 0 : 1);
} catch {
  process.exit(1);
}
