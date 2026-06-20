// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// Native binding smoke test (requires npm run build first).
// Run: node tests/smoke.mjs

import assert from 'node:assert/strict';
import sdk from '../index.js';

const {
  JsDomainName,
  JsNsUpdateSender,
  JsRndcClient,
  JsRndcLimiter,
  JsStatsClient,
  JsTransferClient,
  JsTsigKey,
  JsUpdateBuilder,
  JsZoneFile,
} = sdk;

for (const exported of [
  JsDomainName,
  JsNsUpdateSender,
  JsRndcClient,
  JsRndcLimiter,
  JsStatsClient,
  JsTransferClient,
  JsTsigKey,
  JsUpdateBuilder,
  JsZoneFile,
]) {
  assert.equal(typeof exported, 'function');
}

const d = new JsDomainName('example.com.');
assert.equal(d.toString(), 'example.com.');
assert.equal(d.labelCount(), 3);

const zone = JsZoneFile.parse('$ORIGIN example.com.\nexample.com. 3600 IN A 192.0.2.1\n');
assert.equal(zone.recordCount(), 1);
assert.match(zone.serialize(), /192\.0\.2\.1/);

const key = new JsTsigKey(
  'test-key.',
  'hmac-sha256',
  'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
);
assert.equal(key.name(), 'test-key.');
assert.equal(key.algorithm(), 'hmac-sha256');

const unsigned = new JsUpdateBuilder('example.com.');
unsigned.addRecord('www.example.com.', 300, 'A', '192.0.2.10');
assert.ok(unsigned.buildUnsigned().length > 12);

const signed = new JsUpdateBuilder('example.com.');
signed.addRecord('www.example.com.', 300, 'A', '192.0.2.11');
assert.ok(signed.sign(key).length > 12);

console.log('Smoke test passed');
