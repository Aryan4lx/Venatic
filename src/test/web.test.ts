import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openDb, createDataset, HostWriter, EventWriter, refreshRowCount } from '../store.js';
import { startServe } from '../web/server.js';

// fixture db: one tenant with two dns datasets and one events dataset
const dir = mkdtempSync(join(tmpdir(), 'th-web-'));
const dbPath = join(dir, 'web.db');
const db = openDb(dbPath);

const week1 = createDataset(db, 'acme', 'week1');
const w1 = new HostWriter(db, week1.id);
for (const [h, c] of [['alpha.com', 10], ['beta.com', 5]] as [string, number][]) w1.add(h, c);
w1.flush();
refreshRowCount(db, week1.id);

const week2 = createDataset(db, 'acme', 'week2');
const w2 = new HostWriter(db, week2.id);
for (const [h, c] of [['alpha.com', 30], ['new-c2.evil.net', 99]] as [string, number][]) w2.add(h, c);
w2.flush();
refreshRowCount(db, week2.id);

const ev = createDataset(db, 'acme', 'zeek-test', 'events');
const ew = new EventWriter(db, ev.id);
// a 45-connection beacon at 60s intervals (enough for a high score) + one 2h connection
const start = Date.parse('2026-10-31T10:00:00Z');
for (let i = 0; i < 45; i++) {
  ew.add({ ts: start + i * 60000 + (i % 2) * 500, src_ip: '10.0.0.5', dst_ip: '203.0.113.66', dst_port: 443, proto: 'tcp', duration_ms: 100, bytes_sent: 500, bytes_recv: 5000 });
}
ew.add({ ts: start, src_ip: '10.0.0.9', dst_ip: '10.0.0.2', dst_port: 22, proto: 'tcp', duration_ms: 7200000, bytes_sent: 1, bytes_recv: 1 });
ew.flush();

const server = await startServe({ db: dbPath, port: 0, open: false });
const base = `http://127.0.0.1:${server.port}`;

async function getJson(path: string): Promise<{ status: number; body: any }> {
  const res = await fetch(base + path);
  return { status: res.status, body: await res.json() };
}

test('server serves the dashboard html and chart.js asset', async () => {
  const html = await (await fetch(base + '/')).text();
  assert.ok(html.includes('venatic'), 'app html served');
  const js = await fetch(base + '/chart.umd.js');
  assert.equal(js.status, 200);
  assert.match(js.headers.get('content-type') ?? '', /javascript/);
});

test('GET /api/tenants lists tenants', async () => {
  const { body } = await getJson('/api/tenants');
  assert.deepEqual(body, [{ tenant: 'acme', datasets: 3, hosts: 2 + 2 }]);
});

test('GET /api/datasets filters by tenant', async () => {
  const { body } = await getJson('/api/datasets?tenant=acme');
  assert.equal(body.length, 3);
  assert.ok(body.every((d: any) => d.tenant === 'acme'));
  const { body: none } = await getJson('/api/datasets?tenant=nope');
  assert.deepEqual(none, []);
});

test('GET /api/diff returns counts and sorted sections', async () => {
  const { status, body } = await getJson('/api/diff?tenant=acme&from=week1&to=week2');
  assert.equal(status, 200);
  assert.deepEqual(body.counts, { added: 1, removed: 1, changed: 1, unchanged: 0 });
  assert.equal(body.added[0].hostname, 'new-c2.evil.net');
  assert.equal(body.added[0].count, 99);
  assert.equal(body.removed[0].hostname, 'beta.com');
  assert.equal(body.changed[0].hostname, 'alpha.com');
  assert.deepEqual([body.changed[0].oldCount, body.changed[0].newCount, body.changed[0].delta], [10, 30, 20]);
  assert.equal(body.baseline.label, 'week1');
  assert.equal(body.incoming.label, 'week2');
});

test('GET /api/diff errors are clean 400s', async () => {
  const r1 = await getJson('/api/diff?tenant=acme&from=missing&to=week2');
  assert.equal(r1.status, 400);
  assert.match(r1.body.error, /no dataset 'missing'/);
  const r2 = await getJson('/api/diff');
  assert.equal(r2.status, 400);
  assert.match(r2.body.error, /tenant is required/);
});

test('GET /api/hunt runs each hunt and resolves latest events dataset', async () => {
  const beacon = await getJson('/api/hunt?tenant=acme&name=beaconing&min-conns=20');
  assert.equal(beacon.status, 200);
  assert.equal(beacon.body.dataset.label, 'zeek-test');
  assert.ok(beacon.body.findings.length >= 1, 'planted beacon found');
  const b = beacon.body.findings[0];
  assert.equal(b.dst_ip, '203.0.113.66');
  assert.ok(b.cv < 0.01);
  assert.ok(b.score >= 70);

  const longs = await getJson('/api/hunt?tenant=acme&name=long-conns');
  assert.equal(longs.body.findings.length, 1);
  assert.equal(longs.body.findings[0].durationMs, 7200000);

  const volume = await getJson('/api/hunt?tenant=acme&name=volume');
  const hog = volume.body.findings[0];
  assert.equal(hog.ip, '10.0.0.5');
  assert.equal(hog.medianRatio, 1); // median across 2 hosts is the hog itself

  const dns = await getJson('/api/hunt?tenant=acme&name=dnstunnel');
  assert.deepEqual(dns.body.findings, []); // no dns events planted

  const bad = await getJson('/api/hunt?tenant=acme&name=nonsense');
  assert.equal(bad.status, 400);
  assert.match(bad.body.error, /unknown hunt/);
});

test('server closes cleanly', () => {
  server.close();
  assert.ok(true);
});

// runs after all tests: everything is closed, so the temp dir can go
after(() => {
  db.close();
  try {
    rmSync(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  } catch {
    // windows may still hold the sqlite files briefly; a leftover temp dir is acceptable
  }
});
