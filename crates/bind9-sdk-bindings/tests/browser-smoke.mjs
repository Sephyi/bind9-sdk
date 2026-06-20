// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// Real browser-runtime smoke test for the WASM bundle.
//
// Serves the bindings directory with the COOP/COEP headers that
// SharedArrayBuffer-backed WASM threads require, loads the bundle in headless
// Chromium via Playwright, and asserts the core API works in-browser.
//
// Requires `playwright` with a Chromium browser installed. When Playwright is
// not available (e.g. a sandbox without browser downloads) the test SKIPS with
// a clear message and a non-failing exit code rather than reporting a false
// pass. CI installs Chromium and runs it for real.

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '..'); // crates/bind9-sdk-bindings

let chromium;
try {
  ({ chromium } = await import('playwright'));
} catch {
  console.log('SKIP: playwright not installed; browser runtime not verified here.');
  process.exit(0);
}

const MIME = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.mjs': 'text/javascript',
  '.cjs': 'text/javascript',
  '.wasm': 'application/wasm',
  '.json': 'application/json',
};

const server = createServer(async (req, res) => {
  try {
    const urlPath = decodeURIComponent((req.url || '/').split('?')[0]);
    const rel = normalize(urlPath).replace(/^(\.\.[/\\])+/, '');
    const filePath = join(root, rel);
    const body = await readFile(filePath);
    const ext = filePath.slice(filePath.lastIndexOf('.'));
    // COOP/COEP are mandatory for SharedArrayBuffer (WASM threads).
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
    res.setHeader('Content-Type', MIME[ext] || 'application/octet-stream');
    res.end(body);
  } catch {
    res.statusCode = 404;
    res.end('not found');
  }
});

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const { port } = server.address();
const url = `http://127.0.0.1:${port}/tests/browser/index.html`;

let exitCode = 0;
let browser;
try {
  browser = await chromium.launch();
  const page = await browser.newPage();
  const consoleErrors = [];
  page.on('console', (m) => {
    if (m.type() === 'error') consoleErrors.push(m.text());
  });
  await page.goto(url, { waitUntil: 'load' });
  await page.waitForFunction(() => window.__result !== undefined, { timeout: 30_000 });
  const result = await page.evaluate(() => window.__result);
  if (!result.ok) {
    console.error('Browser test FAILED:', result.detail);
    if (consoleErrors.length) console.error('console errors:', consoleErrors);
    exitCode = 1;
  } else {
    console.log('Browser WASM smoke test passed:', result.detail);
  }
} catch (err) {
  console.error('Browser test harness error:', err);
  exitCode = 1;
} finally {
  if (browser) await browser.close();
  server.close();
}

process.exit(exitCode);
