// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const packageJson = JSON.parse(
  await readFile(new URL('../package.json', import.meta.url), 'utf8'),
);

assert.equal(packageJson.name, 'bind9-sdk');
assert.equal(packageJson.version, '0.1.0');
assert.equal(packageJson.private, false);
assert.equal(packageJson.main, 'index.js');
assert.equal(packageJson.types, 'index.d.ts');
assert.equal(packageJson.browser, 'browser.js');
assert.equal(packageJson.exports['.'].browser, './browser.js');
assert.equal(packageJson.exports['.'].node, './index.js');
assert.equal(packageJson.engines.node, '>=22');
assert.match(packageJson.license, /AGPL-3\.0-only/);

const requiredTargets = [
  'x86_64-unknown-linux-gnu',
  'x86_64-unknown-linux-musl',
  'aarch64-unknown-linux-gnu',
  'aarch64-unknown-linux-musl',
  'x86_64-pc-windows-msvc',
  'x86_64-apple-darwin',
  'aarch64-apple-darwin',
  'wasm32-wasip1-threads',
];
assert.deepEqual(packageJson.napi.targets, requiredTargets);
assert.equal(packageJson.napi.wasm.browser.fs, false);
assert.equal(packageJson.napi.wasm.browser.asyncInit, true);
assert.match(packageJson.scripts['build:wasm'], /--features wasm/);
assert.equal(packageJson.scripts.prepublishOnly, 'napi prepublish -t npm');
