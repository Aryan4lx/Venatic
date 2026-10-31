import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readZeekLog } from '../zeek.js';
import type { EventRow } from '../store.js';

const fixture = 'fixtures/zeek/dns.log';

test('readZeekLog parses tab-delimited zeek directives and maps dns rows', async () => {
  if (!existsSync(fixture)) return; // fixture only present in the repo checkout
  const rows: EventRow[] = [];
  const result = await readZeekLog(fixture, (e) => rows.push(e));
  assert.equal(result.kind, 'dns');
  assert.ok(rows.length > 100, `expected many dns rows, got ${rows.length}`);
  const first = rows[0];
  assert.ok(first.dst_host && first.dst_host.length > 0);
  assert.ok(first.src_ip && first.src_ip.startsWith('10.'));
  assert.ok(first.ts !== null && first.ts !== undefined);
  assert.ok(rows.some((r) => r.rcode === 'NXDOMAIN'));
});
