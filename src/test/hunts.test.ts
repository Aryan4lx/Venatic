import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { entropy, baseDomain, huntBeaconing, huntLongConns, huntVolume, huntDnsTunnel } from '../hunts.js';
import { openDb, createDataset } from '../store.js';

function withTempDb(fn: (db: DatabaseSync, datasetId: number) => void): void {
  const dir = mkdtempSync(join(tmpdir(), 'th-hunt-'));
  const db = openDb(join(dir, 'test.db'));
  try {
    const ds = createDataset(db, 't1', 'events1', 'events');
    fn(db, ds.id);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
  }
}

type EvRow = Partial<Record<'ts' | 'src_ip' | 'dst_ip' | 'dst_port' | 'proto' | 'duration_ms' | 'bytes_sent' | 'bytes_recv' | 'rcode' | 'qtype' | 'dst_host', number | string | null>>;

const insertEvent = (db: DatabaseSync, datasetId: number, row: EvRow): void => {
  db.prepare(
    'INSERT INTO events (dataset_id, ts, src_ip, dst_ip, dst_port, proto, duration_ms, bytes_sent, bytes_recv, rcode, qtype, dst_host) ' +
      'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
  ).run(
    datasetId,
    row.ts ?? null, row.src_ip ?? null, row.dst_ip ?? null, row.dst_port ?? null, row.proto ?? null,
    row.duration_ms ?? null, row.bytes_sent ?? null, row.bytes_recv ?? null, row.rcode ?? null,
    row.qtype ?? null, row.dst_host ?? null,
  );
};

test('entropy measures uniformity in bits per character', () => {
  assert.equal(entropy(''), 0);
  assert.equal(entropy('aaaa'), 0);
  assert.equal(entropy('ab'), 1);
  assert.equal(entropy('abcd'), 2);
});

test('baseDomain reduces to the last two labels and strips dots', () => {
  assert.equal(baseDomain('a.b.example.com'), 'example.com');
  assert.equal(baseDomain('Example.COM.'), 'example.com');
  assert.equal(baseDomain('localhost'), 'localhost');
});

test('huntBeaconing flags regular-interval pairs and skips bursty and same-ms pairs', () => {
  withTempDb((db, ds) => {
    let ts = 1_000_000;
    // beacon: 30 conns every 60s +-1s, similar sizes
    for (let i = 0; i < 30; i++) {
      ts += 60_000 + Math.round(Math.sin(i) * 1000);
      insertEvent(db, ds, { ts, src_ip: '10.0.0.5', dst_ip: '203.0.113.66', dst_port: 443, proto: 'tcp', bytes_sent: 1024, bytes_recv: 4096 });
    }
    // bursty pair: alternating 10s / 120s gaps -> cv ~0.85, must be skipped
    let ts2 = 1_000_000;
    for (let i = 0; i < 30; i++) {
      ts2 += i % 2 === 0 ? 10_000 : 120_000;
      insertEvent(db, ds, { ts: ts2, src_ip: '10.0.0.6', dst_ip: '93.184.216.34', dst_port: 443, proto: 'tcp', bytes_sent: 500, bytes_recv: 20000 });
    }
    // same-millisecond burst: all deltas zero, must be skipped (division guard)
    for (let i = 0; i < 30; i++) {
      insertEvent(db, ds, { ts: 5_000_000, src_ip: '10.0.0.7', dst_ip: '1.1.1.1', dst_port: 53, proto: 'udp' });
    }
    const findings = huntBeaconing(db, ds, { minConns: 20 });
    assert.equal(findings.length, 1);
    assert.equal(findings[0].src_ip, '10.0.0.5');
    assert.equal(findings[0].dst_ip, '203.0.113.66');
    assert.equal(findings[0].conns, 30);
    assert.ok(findings[0].cv < 0.05, `cv should be tiny, got ${findings[0].cv}`);
    assert.ok(findings[0].score >= 70, `beacon should score high, got ${findings[0].score}`);
    assert.ok(findings[0].sizeCv !== null && findings[0].sizeCv < 0.2);
  });
});

test('huntLongConns returns only connections over the threshold, longest first', () => {
  withTempDb((db, ds) => {
    insertEvent(db, ds, { ts: 1, src_ip: '10.0.1.2', dst_ip: '198.51.100.9', dst_port: 8443, proto: 'tcp', duration_ms: 7_200_000 });
    insertEvent(db, ds, { ts: 2, src_ip: '10.0.1.9', dst_ip: '198.51.100.9', dst_port: 443, proto: 'tcp', duration_ms: 59_000 });
    insertEvent(db, ds, { ts: 3, src_ip: '10.0.1.3', dst_ip: '198.51.100.8', dst_port: 22, proto: 'tcp', duration_ms: 3_600_000 * 2.5 });
    const findings = huntLongConns(db, ds, { minDurationMs: 3_600_000 });
    assert.equal(findings.length, 2);
    assert.equal(findings[0].durationMs, 9_000_000);
    assert.equal(findings[0].dst_ip, '198.51.100.8');
    assert.equal(findings[1].durationMs, 7_200_000);
  });
});

test('huntVolume ranks hosts by bytes and computes median ratio', () => {
  withTempDb((db, ds) => {
    // hog: 30 x 1GB
    for (let i = 0; i < 30; i++) insertEvent(db, ds, { src_ip: '10.9.9.9', dst_ip: `172.16.0.${i}`, bytes_sent: 500_000_000, bytes_recv: 500_000_000 });
    // 10 normal hosts x ~1MB
    for (let h = 1; h <= 10; h++) for (let i = 0; i < 4; i++) insertEvent(db, ds, { src_ip: `10.0.0.${h}`, dst_ip: '93.184.216.34', bytes_sent: 130_000, bytes_recv: 130_000 });
    const findings = huntVolume(db, ds, { by: 'src' });
    assert.equal(findings[0].ip, '10.9.9.9');
    assert.equal(findings[0].bytes, 30_000_000_000);
    assert.ok(findings[0].medianRatio > 100);
    const normal = findings.find((f) => f.ip === '10.0.0.1')!;
    assert.ok(normal.medianRatio < 2);
  });
});

test('huntDnsTunnel flags high-entropy multi-label bases over benign ones', () => {
  withTempDb((db, ds) => {
    let ts = 1_000_000;
    // tunnel: 60 unique pseudo-random labels (LCG so the test is deterministic), 1/3 NXDOMAIN, TXT-heavy
    let seed = 12345;
    const next = (): number => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    for (let i = 0; i < 60; i++) {
      const label = Array.from({ length: 24 }, () => chars[Math.floor(next() * chars.length)]).join('');
      insertEvent(db, ds, {
        ts: (ts += 1000),
        src_ip: '10.0.0.5',
        dst_host: `${label}.x7q9k2.evil-c2.net`,
        rcode: i % 3 === 0 ? 'NXDOMAIN' : 'NOERROR',
        qtype: i % 2 === 0 ? 'TXT' : 'A',
      });
    }
    // benign: one base, same single qname repeated
    for (let i = 0; i < 60; i++) insertEvent(db, ds, { ts: (ts += 1000), src_ip: '10.0.0.9', dst_host: 'www.google.com', rcode: 'NOERROR', qtype: 'A' });
    const findings = huntDnsTunnel(db, ds, { minConns: 30 });
    assert.equal(findings.length, 2);
    const tunnel = findings.find((f) => f.base === 'evil-c2.net')!;
    const benign = findings.find((f) => f.base === 'google.com')!;
    assert.equal(tunnel.uniqueQnames, 60);
    assert.equal(benign.uniqueQnames, 1);
    assert.ok(Math.abs(tunnel.nxRatio - 1 / 3) < 0.01);
    assert.ok(tunnel.score > benign.score + 40, `tunnel ${tunnel.score} should crush benign ${benign.score}`);
    assert.ok(tunnel.avgEntropy > 3.5);
  });
});
