import { styleText } from 'node:util';
import type { DatabaseSync } from 'node:sqlite';
import type { Row } from './store.js';
import { fftMagnitudes, nextPow2, standardize, dbscan, pca2, qnameFeatures } from './ml.js';

const useColor = process.stdout.isTTY === true && !process.env.NO_COLOR;
export const c = (color: 'green' | 'red' | 'yellow' | 'gray' | 'cyan', s: string): string => (useColor ? styleText(color, s) : s);

// ---------- shared helpers ----------

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = -1;
  do {
    v /= 1024;
    i++;
  } while (v >= 1024 && i < units.length - 1);
  return `${v.toFixed(1)} ${units[i]}`;
}

export function formatDuration(ms: number): string {
  const s = Math.round(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

/** Shannon entropy of a string, in bits per character. */
export function entropy(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let e = 0;
  for (const f of freq.values()) {
    const p = f / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

/** Naive base-domain: last two labels. Good enough for v1 (shortcut: no PSL). */
export function baseDomain(host: string): string {
  const labels = host.replace(/\.$/, '').toLowerCase().split('.');
  return labels.length <= 2 ? labels.join('.') : labels.slice(-2).join('.');
}

function mean(values: number[]): number {
  return values.reduce((a, b) => a + b, 0) / values.length;
}

function stdev(values: number[]): number {
  if (values.length < 2) return 0;
  const m = mean(values);
  return Math.sqrt(values.reduce((a, b) => a + (b - m) * (b - m), 0) / (values.length - 1));
}

interface HuntOpts {
  limit: number;
  json?: boolean;
}

export function huntHeader(db: DatabaseSync, tenant: string, datasetId: number, title: string): void {
  const ds = db.prepare('SELECT label, imported_at, row_count FROM datasets WHERE id = ?').get(datasetId) as Row;
  console.log('');
  console.log(`tenant:   ${tenant}`);
  console.log(`dataset:  ${String(ds.label)}  (imported ${String(ds.imported_at)}, ${Number(ds.row_count)} events)`);
  console.log(c('cyan', `${title}`));
  console.log('');
}

// ---------- beaconing ----------

export interface BeaconFinding {
  src_ip: string;
  dst_ip: string;
  dst_port: number | null;
  conns: number;
  meanIntervalMs: number;
  jitterMs: number;
  cv: number;
  sizeCv: number | null;
  score: number;
}

/**
 * Beaconing detection: for each (src, dst) pair with enough connections,
 * measure how regular the inter-connection intervals are. Malware C2 checks
 * in at near-fixed intervals (low coefficient of variation of the deltas);
 * human browsing is bursty. Score blends interval regularity, payload size
 * regularity, and a connection-count ramp.
 */
export function huntBeaconing(db: DatabaseSync, datasetId: number, opts: { minConns?: number; maxCv?: number; minIntervalMs?: number; limit?: number } = {}): BeaconFinding[] {
  const minConns = Math.max(2, opts.minConns ?? 20);
  const maxCv = opts.maxCv ?? 0.2;
  const minIntervalMs = opts.minIntervalMs ?? 1000; // sub-second "regular" pairs are bulk/script noise, not C2
  const limit = opts.limit ?? 25;
  const pairs = db
    .prepare(
      'SELECT src_ip, dst_ip, dst_port, COUNT(*) AS c FROM events ' +
        'WHERE dataset_id = ? AND ts IS NOT NULL AND src_ip IS NOT NULL AND dst_ip IS NOT NULL ' +
        'GROUP BY src_ip, dst_ip HAVING COUNT(*) >= ?',
    )
    .all(datasetId, minConns) as Row[];
  const tsStmt = db.prepare('SELECT ts FROM events WHERE dataset_id = ? AND src_ip = ? AND dst_ip = ? AND ts IS NOT NULL ORDER BY ts');
  const sizeStmt = db.prepare(
    'SELECT bytes_sent + bytes_recv AS b FROM events WHERE dataset_id = ? AND src_ip = ? AND dst_ip = ? AND bytes_sent IS NOT NULL AND bytes_recv IS NOT NULL',
  );
  const findings: BeaconFinding[] = [];
  for (const p of pairs) {
    const ts = (tsStmt.all(datasetId, String(p.src_ip), String(p.dst_ip)) as Row[]).map((r) => Number(r.ts));
    if (ts.length < minConns) continue;
    const deltas: number[] = [];
    for (let i = 1; i < ts.length; i++) deltas.push(ts[i] - ts[i - 1]);
    const m = mean(deltas);
    if (m <= 0 || m < minIntervalMs) continue; // all-zero same-ms burst, or too fast to be a check-in
    const sd = stdev(deltas);
    const cv = sd / m;
    if (cv > maxCv) continue;
    let sizeCv: number | null = null;
    const sizes = (sizeStmt.all(datasetId, String(p.src_ip), String(p.dst_ip)) as Row[]).map((r) => Number(r.b));
    if (sizes.length >= minConns) {
      const sm = mean(sizes);
      if (sm > 0) sizeCv = stdev(sizes) / sm;
    }
    const intervalReg = 1 - Math.min(1, cv);
    const sizeReg = sizeCv === null ? 0.5 : 1 - Math.min(1, sizeCv);
    const score = Math.round((0.7 * intervalReg + 0.3 * sizeReg) * Math.min(1, ts.length / 40) * 100);
    findings.push({ src_ip: String(p.src_ip), dst_ip: String(p.dst_ip), dst_port: p.dst_port === null ? null : Number(p.dst_port), conns: ts.length, meanIntervalMs: Math.round(m), jitterMs: Math.round(sd), cv, sizeCv, score });
  }
  findings.sort((a, b) => b.score - a.score);
  return findings.slice(0, limit);
}

export function renderBeaconing(f: BeaconFinding[], o: HuntOpts): void {
  if (o.json) return void console.log(JSON.stringify(f, null, 2));
  console.log(`beaconing candidates: ${f.length}${f.length ? '  (score = interval regularity + size regularity + conn count)' : ''}\n`);
  for (const x of f) {
    const sev = x.score >= 70 ? c('red', `score ${x.score}`) : x.score >= 40 ? c('yellow', `score ${x.score}`) : c('gray', `score ${x.score}`);
    console.log(`${sev}  ${x.src_ip} -> ${x.dst_ip}${x.dst_port ? `:${x.dst_port}` : ''}`);
    console.log(`     ${x.conns} conns | mean every ${formatDuration(x.meanIntervalMs)} (jitter ${formatDuration(x.jitterMs)}, cv ${x.cv.toFixed(3)})${x.sizeCv !== null ? ` | size cv ${x.sizeCv.toFixed(3)}` : ''}`);
  }
}

// ---------- long connections ----------

export interface LongConnFinding {
  src_ip: string;
  dst_ip: string;
  dst_port: number | null;
  proto: string | null;
  durationMs: number;
  bytesSent: number | null;
  bytesRecv: number | null;
}

export function huntLongConns(db: DatabaseSync, datasetId: number, opts: { minDurationMs?: number; limit?: number } = {}): LongConnFinding[] {
  const min = opts.minDurationMs ?? 3600 * 1000;
  const rows = db
    .prepare(
      'SELECT src_ip, dst_ip, dst_port, proto, duration_ms, bytes_sent, bytes_recv FROM events ' +
        'WHERE dataset_id = ? AND duration_ms >= ? ORDER BY duration_ms DESC LIMIT ?',
    )
    .all(datasetId, min, opts.limit ?? 50) as Row[];
  return rows.map((r) => ({
    src_ip: String(r.src_ip ?? '?'),
    dst_ip: String(r.dst_ip ?? '?'),
    dst_port: r.dst_port === null || r.dst_port === undefined ? null : Number(r.dst_port),
    proto: r.proto === null || r.proto === undefined ? null : String(r.proto),
    durationMs: Number(r.duration_ms),
    bytesSent: r.bytes_sent === null || r.bytes_sent === undefined ? null : Number(r.bytes_sent),
    bytesRecv: r.bytes_recv === null || r.bytes_recv === undefined ? null : Number(r.bytes_recv),
  }));
}

export function renderLongConns(f: LongConnFinding[], o: HuntOpts): void {
  if (o.json) return void console.log(JSON.stringify(f, null, 2));
  console.log(`long connections: ${f.length}\n`);
  for (const x of f) {
    console.log(`${c('yellow', formatDuration(x.durationMs).padEnd(10))}  ${x.src_ip} -> ${x.dst_ip}${x.dst_port ? `:${x.dst_port}` : ''} ${c('gray', `${x.proto ?? ''}  sent ${x.bytesSent !== null ? formatBytes(x.bytesSent) : '-'}  recv ${x.bytesRecv !== null ? formatBytes(x.bytesRecv) : '-'}`)}`);
  }
}

// ---------- volume outliers ----------

export interface VolumeFinding {
  ip: string;
  bytes: number;
  conns: number;
  medianRatio: number;
}

/**
 * Volume outliers: total transferred bytes per host (src or dst side), ranked
 * against the median. A host moving 100x the median traffic is exfil,
 * staging, or policy violation - all worth a look.
 */
export function huntVolume(db: DatabaseSync, datasetId: number, opts: { by?: 'src' | 'dst'; limit?: number } = {}): VolumeFinding[] {
  const col = opts.by === 'dst' ? 'dst_ip' : 'src_ip';
  const rows = db
    .prepare(
      `SELECT ${col} AS ip, SUM(COALESCE(bytes_sent, 0) + COALESCE(bytes_recv, 0)) AS bytes, COUNT(*) AS conns
       FROM events WHERE dataset_id = ? AND ${col} IS NOT NULL GROUP BY ${col} ORDER BY bytes DESC`,
    )
    .all(datasetId) as Row[];
  const totals = rows.map((r) => Number(r.bytes)).sort((a, b) => a - b);
  const median = totals.length ? totals[Math.floor(totals.length / 2)] : 0;
  return rows.slice(0, opts.limit ?? 20).map((r) => ({
    ip: String(r.ip),
    bytes: Number(r.bytes),
    conns: Number(r.conns),
    // median 0 (e.g. deny-heavy firewalls) -> Infinity for any traffic at all
    medianRatio: median > 0 ? Number(r.bytes) / median : Number(r.bytes) > 0 ? Infinity : 0,
  }));
}

export function renderVolume(f: VolumeFinding[], o: HuntOpts): void {
  if (o.json) return void console.log(JSON.stringify(f, null, 2));
  console.log(`top hosts by transferred bytes: ${f.length}\n`);
  for (const x of f) {
    const flag = x.medianRatio >= 10 ? c('red', '!!') : x.medianRatio >= 3 ? c('yellow', '! ') : '  ';
    const ratio = x.medianRatio === Infinity ? 'infinity x median' : `${x.medianRatio.toFixed(1)}x median`;
    console.log(`${flag} ${x.ip.padEnd(18)} ${formatBytes(x.bytes).padStart(12)}  ${c('gray', `${x.conns} conns, ${ratio}`)}`);
  }
}

// ---------- fft beacons ----------

export interface FftBeaconFinding {
  src_ip: string;
  dst_ip: string;
  dst_port: number | null;
  conns: number;
  spanMs: number;
  periodMs: number;
  peakRatio: number;
  score: number;
}

/**
 * FFT beaconing (Hoelzer's "old data, new tricks"): bin each (src,dst) pair's
 * connection timestamps into a fixed-width time series and run a discrete
 * Fourier transform over it. A machine checking in on a schedule spikes one
 * frequency bin even when its jitter is too high for interval-CV detection.
 * Bin 0 (DC) is ignored - it is an artifact on real-valued input.
 */
export function huntFftBeacons(db: DatabaseSync, datasetId: number, opts: { minConns?: number; minPeakRatio?: number; limit?: number } = {}): FftBeaconFinding[] {
  const minConns = Math.max(16, opts.minConns ?? 60);
  const minPeakRatio = opts.minPeakRatio ?? 3;
  const limit = opts.limit ?? 25;
  const pairs = db
    .prepare(
      'SELECT src_ip, dst_ip, dst_port, COUNT(*) AS c, MIN(ts) AS lo, MAX(ts) AS hi FROM events ' +
        'WHERE dataset_id = ? AND ts IS NOT NULL AND src_ip IS NOT NULL AND dst_ip IS NOT NULL ' +
        'GROUP BY src_ip, dst_ip HAVING COUNT(*) >= ?',
    )
    .all(datasetId, minConns) as Row[];
  const tsStmt = db.prepare('SELECT ts FROM events WHERE dataset_id = ? AND src_ip = ? AND dst_ip = ? AND ts IS NOT NULL ORDER BY ts');
  const findings: FftBeaconFinding[] = [];
  for (const p of pairs) {
    const conns = Number(p.c);
    const spanMs = Number(p.hi) - Number(p.lo);
    if (spanMs <= 0) continue;
    const ts = (tsStmt.all(datasetId, String(p.src_ip), String(p.dst_ip)) as Row[]).map((r) => Number(r.ts));
    // ~2 bins per connection so the bin width stays below half the period
    // (a 144-conn beacon over 2 days needs sub-6-minute bins)
    const bins = Math.max(16, Math.min(512, nextPow2(conns * 2)));
    const binMs = spanMs / bins;
    const signal = new Array<number>(bins).fill(0);
    for (const t of ts) signal[Math.min(bins - 1, Math.floor((t - Number(p.lo)) / binMs))]++;
    const mags = fftMagnitudes(signal);
    // skip bin 0 (DC) and bin 1 (single whole-span cycle = trend, not a beacon)
    const body = mags.slice(2, mags.length - 1); // last bin is Nyquist mirror
    const floor = median(body);
    if (floor <= 0) continue;
    let peakBin = 2;
    let peak = mags[2];
    for (let k = 3; k < mags.length - 1; k++) {
      if (mags[k] > peak) {
        peak = mags[k];
        peakBin = k;
      }
    }
    const peakRatio = peak / floor;
    if (peakRatio < minPeakRatio) continue;
    // a real schedule repeats several times over the window; a 1-2 bin period
    // against the whole span is a burst artifact
    const periodMs = spanMs / peakBin;
    if (peakBin < 2 || spanMs / periodMs < 3) continue;
    const score = Math.round(Math.min(1, Math.log2(peakRatio) / Math.log2(20)) * 60 + Math.min(1, conns / 120) * 40);
    findings.push({
      src_ip: String(p.src_ip),
      dst_ip: String(p.dst_ip),
      dst_port: p.dst_port === null ? null : Number(p.dst_port),
      conns,
      spanMs,
      periodMs: Math.round(periodMs),
      peakRatio: Math.round(peakRatio * 10) / 10,
      score,
    });
  }
  findings.sort((a, b) => b.score - a.score);
  return findings.slice(0, limit);
}

function median(values: number[]): number {
  if (!values.length) return 0;
  const s = [...values].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

export function renderFftBeacons(f: FftBeaconFinding[], o: HuntOpts): void {
  if (o.json) return void console.log(JSON.stringify(f, null, 2));
  console.log(`fft beacon candidates: ${f.length}  (spectral peak vs noise floor; catches jitter the interval-cv hunt misses)\n`);
  for (const x of f) {
    const sev = x.score >= 70 ? c('red', `score ${x.score}`) : x.score >= 40 ? c('yellow', `score ${x.score}`) : c('gray', `score ${x.score}`);
    console.log(`${sev}  ${x.src_ip} -> ${x.dst_ip}${x.dst_port ? `:${x.dst_port}` : ''}`);
    console.log(`     ${x.conns} conns over ${formatDuration(x.spanMs)} | repeating every ${formatDuration(x.periodMs)} | peak ${x.peakRatio}x noise floor`);
  }
}

// ---------- dns clustering ----------

export interface DnsClusterFinding {
  cluster: number;
  size: number;
  meanEntropy: number;
  meanMaxLabel: number;
  meanDigitRatio: number;
  meanRarity: number;
  weirdness: number;
  samples: string[];
}

export interface DnsClusterResult {
  uniqueQnames: number;
  clustered: number;
  noise: number;
  clusters: DnsClusterFinding[];
  outliers: { qname: string; rarity: number; entropy: number }[];
  scatter: { q: string; x: number; y: number; c: number }[]; // pca projection for the dashboard
}

const FEATURES = ['length', 'labels', 'maxLabel', 'entropy', 'digitRatio', 'rarity'] as const;

/**
 * Hoelzer's DBSCAN approach: engineer numeric features per unique DNS query
 * name, density-cluster the population, and let "the weird" fall into its own
 * small clusters (iodine-style tunnels always did in his demos). Noise points
 * are the other place to look. Unsupervised - no labels, no baseline.
 */
export function huntDnsClusters(db: DatabaseSync, datasetId: number, opts: { eps?: number; minPts?: number; maxPoints?: number; limit?: number } = {}): DnsClusterResult {
  const eps = opts.eps ?? 1.1;
  const minPts = opts.minPts ?? 4;
  const maxPoints = opts.maxPoints ?? 20000;
  const limit = opts.limit ?? 25;
  const rows = db
    .prepare('SELECT DISTINCT dst_host AS q FROM events WHERE dataset_id = ? AND dst_host IS NOT NULL')
    .all(datasetId) as Row[];
  const names = rows
    .map((r) => String(r.q).toLowerCase())
    .filter((q) => q.includes('.') && !/^[0-9.]+$/.test(q) && !q.endsWith('.arpa') && !/\.(local|lan|home|internal|intranet)$/.test(q));
  const uniq = [...new Set(names)];
  const result: DnsClusterResult = { uniqueQnames: uniq.length, clustered: 0, noise: 0, clusters: [], outliers: [], scatter: [] };
  if (uniq.length < minPts + 2) return result;
  // sample for the O(n^2) clustering step, deterministic by hash so reruns match
  let pool = uniq;
  if (uniq.length > maxPoints) {
    const stride = uniq.length / maxPoints;
    pool = [];
    for (let i = 0; i < maxPoints; i++) pool.push(uniq[Math.floor(i * stride)]); // deterministic stride sample
  }
  const feats = pool.map(qnameFeatures);
  const vectors = feats.map((f) => [f.length, f.labels, f.maxLabel, f.entropy, f.digitRatio, f.rarity]);
  const { data } = standardize(vectors);
  const labels = dbscan(data, eps, minPts);
  const byCluster = new Map<number, number[]>();
  const noiseIdx: number[] = [];
  labels.forEach((l, i) => {
    if (l >= 0) {
      let a = byCluster.get(l);
      if (!a) byCluster.set(l, (a = []));
      a.push(i);
    } else if (l === -1) noiseIdx.push(i);
  });
  const maxRarity = Math.max(...feats.map((f) => f.rarity), 0.001);
  for (const [cid, idxs] of byCluster) {
    const avg = (pick: (f: (typeof feats)[number]) => number): number => idxs.reduce((a, i) => a + pick(feats[i]), 0) / idxs.length;
    const weirdness = avg((f) => f.rarity / maxRarity) + avg((f) => Math.min(1, f.entropy / 5)) + avg((f) => f.digitRatio);
    result.clusters.push({
      cluster: cid,
      size: idxs.length,
      meanEntropy: avg((f) => f.entropy),
      meanMaxLabel: avg((f) => f.maxLabel),
      meanDigitRatio: avg((f) => f.digitRatio),
      meanRarity: avg((f) => f.rarity),
      weirdness: Math.round(weirdness * 100) / 100,
      samples: idxs.slice(0, 5).map((i) => feats[i].qname),
    });
  }
  result.clusters.sort((a, b) => b.weirdness - a.weirdness);
  result.clusters = result.clusters.slice(0, limit);
  result.outliers = noiseIdx
    .map((i) => ({ qname: feats[i].qname, rarity: feats[i].rarity, entropy: feats[i].entropy }))
    .sort((a, b) => b.rarity + b.entropy / 5 - (a.rarity + a.entropy / 5))
    .slice(0, 15);
  result.noise = noiseIdx.length;
  result.clustered = pool.length - noiseIdx.length;
  const { proj } = pca2(data);
  const scatterCap = 2000;
  result.scatter = proj
    .slice(0, scatterCap)
    .map((p, i) => ({ q: feats[i].qname, x: Math.round(p.x * 100) / 100, y: Math.round(p.y * 100) / 100, c: labels[i] }));
  return result;
}

export function renderDnsClusters(r: DnsClusterResult, o: HuntOpts): void {
  if (o.json) return void console.log(JSON.stringify(r, null, 2));
  console.log(`dns clustering: ${r.uniqueQnames} unique names -> ${r.clusters.length} clusters, ${r.noise} noise outliers${r.uniqueQnames > 20000 ? ' (sampled 20000)' : ''}\n`);
  for (const cl of r.clusters) {
    const sev = cl.weirdness >= 1.5 ? c('red', `cluster ${cl.cluster}`) : cl.weirdness >= 1.0 ? c('yellow', `cluster ${cl.cluster}`) : c('gray', `cluster ${cl.cluster}`);
    console.log(`${sev}  ${cl.size} names | entropy ${cl.meanEntropy.toFixed(2)} | max label ${cl.meanMaxLabel.toFixed(0)} chars | digits ${(cl.meanDigitRatio * 100).toFixed(0)}% | rarity ${cl.meanRarity.toFixed(2)} | weirdness ${cl.weirdness}`);
    console.log(`     e.g. ${cl.samples.join(', ')}`);
  }
  if (r.outliers.length) {
    console.log(`\ntop lone outliers (noise) - each stands alone in feature space:`);
    for (const x of r.outliers) console.log(`  ${x.qname}  ${c('gray', `(entropy ${x.entropy.toFixed(2)}, rarity ${(x.rarity * 100).toFixed(0)}%)`)}`);
  }
}

// ---------- dns tunneling / dga ----------

export interface DnsFinding {
  base: string;
  uniqueQnames: number;
  conns: number;
  nxRatio: number;
  txtShare: number;
  maxLabelLen: number;
  avgEntropy: number;
  score: number;
}

/**
 * DNS tunneling/DGA detection: per base domain, count unique query names,
 * NXDOMAIN ratio, TXT share, and subdomain label length/entropy. Tunnels
 * (dnscat2, iodine) produce many unique high-entropy labels under one base;
 * DGAs produce mostly-NXDOMAIN hammers across lookalike bases.
 */
export function huntDnsTunnel(db: DatabaseSync, datasetId: number, opts: { minConns?: number; limit?: number } = {}): DnsFinding[] {
  const minConns = Math.max(1, opts.minConns ?? 30);
  const limit = opts.limit ?? 25;
  const perQname = db
    .prepare(
      'SELECT dst_host AS q, COUNT(*) AS c, SUM(CASE WHEN rcode = \'NXDOMAIN\' OR rcode = \'3\' THEN 1 ELSE 0 END) AS nx, SUM(CASE WHEN qtype = \'TXT\' THEN 1 ELSE 0 END) AS txt ' +
        'FROM events WHERE dataset_id = ? AND dst_host IS NOT NULL GROUP BY dst_host',
    )
    .iterate(datasetId) as IterableIterator<Row>;
  const bases = new Map<string, { c: number; nx: number; txt: number; u: number; maxLabel: number; entSum: number }>();
  for (const r of perQname) {
    const q = String(r.q).toLowerCase();
    // reverse-lookup zones (PTR) create huge unique-name counts but can't carry tunnel data;
    // IP literals (fortios logs blocked queries as dst_host 0.0.0.0) are not names either
    if (q.endsWith('.arpa') || /^[0-9.]+$/.test(q)) continue;
    const b = baseDomain(q);
    const cnt = Number(r.c);
    let st = bases.get(b);
    if (!st) {
      st = { c: 0, nx: 0, txt: 0, u: 0, maxLabel: 0, entSum: 0 };
      bases.set(b, st);
    }
    st.c += cnt;
    st.nx += Number(r.nx);
    st.txt += Number(r.txt);
    st.u += 1;
    // data-carrying label = everything except the base domain part
    const sub = q.length > b.length ? q.slice(0, q.length - b.length - 1) : '';
    const longest = sub.split('.').reduce((m, l) => Math.max(m, l.length), 0);
    st.maxLabel = Math.max(st.maxLabel, longest);
    st.entSum += entropy(sub) * cnt;
  }
  const out: DnsFinding[] = [];
  for (const [base, st] of bases) {
    if (st.c < minConns) continue;
    const avgEntropy = st.entSum / st.c;
    const nxRatio = st.nx / st.c;
    const txtShare = st.txt / st.c;
    const score = Math.round(
      (0.4 * Math.min(1, st.u / 500) + 0.3 * Math.min(1, avgEntropy / 4) + 0.2 * nxRatio + 0.1 * txtShare) * 100,
    );
    out.push({ base, uniqueQnames: st.u, conns: st.c, nxRatio, txtShare, maxLabelLen: st.maxLabel, avgEntropy, score });
  }
  out.sort((a, b) => b.score - a.score);
  return out.slice(0, limit);
}

export function renderDnsTunnel(f: DnsFinding[], o: HuntOpts): void {
  if (o.json) return void console.log(JSON.stringify(f, null, 2));
  console.log(`dns tunneling / dga candidates: ${f.length}\n`);
  for (const x of f) {
    const sev = x.score >= 60 ? c('red', `score ${x.score}`) : x.score >= 35 ? c('yellow', `score ${x.score}`) : c('gray', `score ${x.score}`);
    console.log(`${sev}  ${x.base}`);
    console.log(`     ${x.conns} queries | ${x.uniqueQnames} unique names | nx ${(x.nxRatio * 100).toFixed(0)}% | max label ${x.maxLabelLen} chars | avg entropy ${x.avgEntropy.toFixed(2)} | txt ${(x.txtShare * 100).toFixed(0)}%`);
  }
}
