import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fftMagnitudes, nextPow2, dbscan, standardize, pca2, qnameFeatures } from '../ml.js';
import { huntFftBeacons, huntDnsClusters } from '../hunts.js';
import { trainAutoencoder, scoreHosts } from '../nn.js';
import { openDb, createDataset } from '../store.js';

function withTempDb(fn: (db: DatabaseSync, datasetId: number, dbPath: string) => void | Promise<void>): void | Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), 'th-ml-'));
  const dbPath = join(dir, 'test.db');
  const db = openDb(dbPath);
  const run = async () => {
    try {
      const ds = createDataset(db, 't1', 'events1', 'events');
      await fn(db, ds.id, dbPath);
    } finally {
      db.close();
      rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
    }
  };
  return run();
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

// ---------- pure math ----------

test('fft finds the injected periodic component', () => {
  const bins = 64;
  const period = 8; // every 8th bin
  const signal = new Array<number>(bins).fill(0);
  for (let i = period; i < bins; i += period) signal[i] = 10;
  for (let i = 0; i < bins; i++) signal[i] += 1; // background
  const mags = fftMagnitudes(signal);
  assert.equal(mags.length, bins / 2 + 1);
  // peak should sit at bin = bins/period = 8 (DC bin 0 excluded)
  let best = 1;
  for (let k = 2; k < mags.length - 1; k++) if (mags[k] > mags[best]) best = k;
  assert.equal(best, bins / period);
});

test('fft pads non-power-of-two signals', () => {
  const mags = fftMagnitudes(new Array<number>(100).fill(1));
  assert.equal(mags.length, nextPow2(100) / 2 + 1);
});

test('dbscan separates two blobs and flags noise', () => {
  const points: number[][] = [];
  for (let i = 0; i < 20; i++) points.push([Math.cos(i) * 0.1, Math.sin(i) * 0.1]); // blob around origin
  for (let i = 0; i < 20; i++) points.push([10 + Math.cos(i) * 0.1, 10 + Math.sin(i) * 0.1]); // blob at (10,10)
  points.push([50, 50], [-30, 4], [7, -22]); // true outliers
  const labels = dbscan(points, 1.0, 4);
  assert.equal(new Set(labels.slice(0, 20)).size, 1);
  assert.equal(labels[0], labels[1]);
  assert.equal(labels[0] !== labels[20], true);
  for (const i of [40, 41, 42]) assert.equal(labels[i], -1);
});

test('standardize z-scores and guards constant dimensions', () => {
  const { data, stds } = standardize([
    [1, 5, 2], [3, 5, 4], [5, 5, 6],
  ]);
  assert.equal(stds[1], 1); // constant dim forced to 1
  assert.equal(Math.abs(data[0][0] + data[1][0] + data[2][0]) < 1e-9, true); // zero mean
});

test('pca2 projects correlated data mostly onto pc1', () => {
  const pts: number[][] = [];
  for (let i = 0; i < 50; i++) {
    const t = i / 50;
    pts.push([t * 10 + 0.001 * Math.sin(i), t * 10 - 0.001 * Math.cos(i)]);
  }
  const { data } = standardize(pts);
  const { explained } = pca2(data);
  assert.ok(explained[0] > 0.9, `pc1 should dominate, got ${explained[0]}`);
  assert.ok(explained[0] >= explained[1]);
});

test('qname features separate machine-ish names from human ones', () => {
  const dga = qnameFeatures('x7q9k2b1v3m8w5.evil-base.net');
  const human = qnameFeatures('mail.google.com');
  assert.ok(dga.entropy > human.entropy);
  assert.ok(dga.digitRatio > human.digitRatio);
  assert.ok(dga.rarity > human.rarity);
  assert.equal(qnameFeatures('A.BC.example.').qname, 'a.bc.example'); // case + trailing dot normalized
});

// ---------- hunts on a synthetic db ----------

test('fft beacon hunt finds a jittered beacon the cv hunt would struggle with', () => {
  return withTempDb((db, dsId) => {
    const base = 1700000000000;
    const periodMs = 20 * 60 * 1000;
    const span = 48 * 3600 * 1000;
    // jittered check-in: period +/- up to 6 min (cv too high for the strict hunt)
    let t = base;
    while (t < base + span) {
      insertEvent(db, dsId, { ts: Math.round(t), src_ip: '10.0.0.5', dst_ip: '198.51.100.9', dst_port: 443, proto: 'tcp', duration_ms: 30000, bytes_sent: 500, bytes_recv: 2000 });
      t += periodMs + (Math.sin(t / 9e7) * 0.3 + Math.cos(t / 2.3e7) * 0.3) * 6 * 60 * 1000;
    }
    // background noise from another host
    for (let i = 0; i < 200; i++) {
      insertEvent(db, dsId, { ts: base + Math.floor(Math.sin(i * 7.3) * span / 2 + span / 2), src_ip: '10.0.0.9', dst_ip: `198.51.100.${i % 20}`, dst_port: 80, proto: 'tcp' });
    }
    const findings = huntFftBeacons(db, dsId, { minConns: 60 });
    assert.ok(findings.length >= 1, 'should find the beacon pair');
    const f = findings.find((x) => x.src_ip === '10.0.0.5' && x.dst_ip === '198.51.100.9');
    assert.ok(f, 'beacon pair in findings');
    // period within 25% of the true 20 minutes
    assert.ok(Math.abs(f!.periodMs - periodMs) < periodMs * 0.25, `period ${f!.periodMs} vs ${periodMs}`);
    assert.ok(f!.peakRatio >= 3);
  });
});

test('dns cluster hunt puts algorithmic names in their own cluster', () => {
  return withTempDb((db, dsId) => {
    const base = 1700000000000;
    // normal enterprise traffic
    const normal = ['mail.google.com', 'www.microsoft.com', 'updates.office.com', 'login.salesforce.com', 'cdn.jsdelivr.net', 'slack.com', 'zoom.us', 'docs.google.com'];
    for (let i = 0; i < 80; i++) {
      for (const q of normal) {
        insertEvent(db, dsId, { ts: base + i * 60000, src_ip: '10.0.0.2', dst_ip: '1.2.3.4', rcode: 'NOERROR', qtype: 'A', dst_host: q });
      }
    }
    // dga-ish tunnel names
    for (let i = 0; i < 15; i++) {
      const label = [...Array(4)].map(() => String.fromCharCode(97 + ((i * 7 + 3) % 26))).join('') + i;
      insertEvent(db, dsId, { ts: base + i * 60000, src_ip: '10.0.0.66', dst_ip: '6.6.6.6', rcode: 'NOERROR', qtype: 'TXT', dst_host: `${label}.zy9x2m.badguy.net` });
    }
    // ptr records excluded
    insertEvent(db, dsId, { ts: base, src_ip: '10.0.0.2', dst_ip: '1.2.3.4', rcode: 'NOERROR', qtype: 'PTR', dst_host: '4.3.2.1.in-addr.arpa' });
    const res = huntDnsClusters(db, dsId);
    assert.equal(res.uniqueQnames, 8 + 15);
    const weird = res.clusters.find((c) => c.samples.some((s) => s.includes('zy9x2m')));
    assert.ok(weird, 'algorithmic names cluster together');
    assert.ok(weird!.meanDigitRatio > 0, 'digit-heavy cluster');
    assert.ok(res.noise >= 0);
  });
});

// ---------- autoencoder ----------

test('autoencoder trains on host profiles and ranks the outlier first', () => {
  return withTempDb(async (db, dsId, dbPath) => {
    const base = 1700000000000;
    // 30 ordinary hosts: low volume, mostly tcp web
    for (let h = 0; h < 30; h++) {
      for (let i = 0; i < 20; i++) {
        insertEvent(db, dsId, { ts: base + i * 3600000, src_ip: `10.0.${Math.floor(h / 50)}.${h % 50 + 1}`, dst_ip: `93.184.216.${i % 8}`, dst_port: 443, proto: 'tcp', duration_ms: 500 + i, bytes_sent: 800, bytes_recv: 4000 });
      }
    }
    // one exfil-ish host: huge volumes, many destinations, night hours
    for (let i = 0; i < 200; i++) {
      insertEvent(db, dsId, { ts: base + (i % 4) * 3600000, src_ip: '10.0.0.250', dst_ip: `45.77.${i % 30}.${i % 17}`, dst_port: 8443, proto: 'tcp', duration_ms: 100, bytes_sent: 500000, bytes_recv: 100 });
    }
    const train = await trainAutoencoder(db, dsId, dbPath, 't1', 'events1', 12);
    assert.equal(train.hosts, 31);
    assert.ok(Number.isFinite(train.finalLoss));
    const findings = await scoreHosts(db, dsId, dbPath, 't1', 5);
    assert.equal(findings.length, 5);
    assert.equal(findings[0].ip, '10.0.0.250', 'exfil host ranks first');
    assert.ok(findings[0].score > findings[findings.length - 1].score);
    assert.ok(findings[0].topDeviations.length >= 1);
  });
});
