// SPDX-FileCopyrightText: 2026 Sephyi <me@sephy.io>
//
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

// Basic smoke test for napi bindings (requires npm run build first).
// Run: node tests/smoke.mjs

import { JsDomainName, JsZoneFile } from '../index.js';

const d = new JsDomainName('example.com.');
console.assert(d.toString() === 'example.com.', 'DomainName toString failed');
console.assert(d.labelCount() === 3, 'DomainName labelCount failed');

const zone = JsZoneFile.parse('$ORIGIN example.com.\nexample.com. 3600 IN A 192.0.2.1\n');
console.assert(zone.recordCount() >= 1, 'ZoneFile recordCount failed');

console.log('Smoke test passed');
