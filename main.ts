import { createForgeServer } from './forge.ts';

// Lifecycle only: bind a port, register with the harness, poll /done, exit 0.
// Standalone (no MAKEFUN_ENV_URL): listen on FORGE_PORT or 18080 and keep serving.

const envUrl = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
const server = createForgeServer();

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
});

if (envUrl === '') {
  const port = Number(process.env.FORGE_PORT ?? '18080');
  server.listen(port, '127.0.0.1', () => {
    console.log(`forge listening standalone on 127.0.0.1:${port}`);
  });
} else {
  server.listen(0, '127.0.0.1', async () => {
    const address = server.address();
    const port = typeof address === 'object' && address !== null ? address.port : 0;
    try {
      const res = await fetch(`${envUrl}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
      });
      if (!res.ok) {
        console.error(`register failed: HTTP ${res.status}`);
        process.exit(1);
      }
    } catch (err) {
      console.error(`register failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }
    console.log(`forge listening on 127.0.0.1:${port}, registered with ${envUrl}`);
    for (;;) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      try {
        const done = await fetch(`${envUrl}/done`);
        if (done.ok) {
          const body = (await done.json().catch(() => null)) as { done?: boolean } | null;
          if (body === null || body.done !== false) break;
        }
      } catch {
        // Keep polling through transient errors.
      }
    }
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  });
}
