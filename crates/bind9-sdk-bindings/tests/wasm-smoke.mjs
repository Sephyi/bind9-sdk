// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const sdk = require('../bind9-sdk.wasi.cjs');

for (const name of [
  'JsDomainName',
  'JsTsigKey',
  'JsUpdateBuilder',
  'JsUpdateMessage',
  'JsZoneFile',
]) {
  assert.equal(typeof sdk[name], 'function', `${name} must be exported`);
}

for (const name of [
  'JsNsUpdateSender',
  'JsRndcClient',
  'JsRndcLimiter',
  'JsStatsClient',
  'JsTransferClient',
]) {
  assert.equal(sdk[name], undefined, `${name} must not be exported in WASM`);
}

const domain = new sdk.JsDomainName('wasm.example.');
assert.equal(domain.toString(), 'wasm.example.');

const zone = sdk.JsZoneFile.parse(
  '$ORIGIN wasm.example.\nwasm.example. 300 IN A 192.0.2.1\n',
);
assert.equal(zone.recordCount(), 1);
assert.match(zone.serialize(), /192\.0\.2\.1/);

const builder = new sdk.JsUpdateBuilder('wasm.example.');
builder.addRecord('www.wasm.example.', 300, 'AAAA', '2001:db8::1');
assert.ok(builder.buildUnsigned().length > 12);

console.log('WASM smoke test passed');
