import { styleText } from 'node:util';
import type { DatabaseSync } from 'node:sqlite';
import type { Row } from './store.js';

const useColor = process.stdout.isTTY === true && !process.env.NO_COLOR;
const c = (color: 'green' | 'red' | 'yellow' | 'gray' | 'cyan', s: string): string => (useColor ? styleText(color, s) : s);

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
    medianRatio: median > 0 ? Number(r.bytes) / median : 0,
  }));
}

export function renderVolume(f: VolumeFinding[], o: HuntOpts): void {
  if (o.json) return void console.log(JSON.stringify(f, null, 2));
  console.log(`top hosts by transferred bytes: ${f.length}\n`);
  for (const x of f) {
    const flag = x.medianRatio >= 10 ? c('red', '!!') : x.medianRatio >= 3 ? c('yellow', '! ') : '  ';
    console.log(`${flag} ${x.ip.padEnd(18)} ${formatBytes(x.bytes).padStart(12)}  ${c('gray', `${x.conns} conns, ${x.medianRatio.toFixed(1)}x median`)}`);
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
      "SELECT dst_host AS q, COUNT(*) AS c, SUM(CASE WHEN rcode = 'NXDOMAIN' THEN 1 ELSE 0 END) AS nx, SUM(CASE WHEN qtype = 'TXT' THEN 1 ELSE 0 END) AS txt " +
        'FROM events WHERE dataset_id = ? AND rcode IS NOT NULL AND dst_host IS NOT NULL GROUP BY dst_host',
    )
    .iterate(datasetId) as IterableIterator<Row>;
  const bases = new Map<string, { c: number; nx: number; txt: number; u: number; maxLabel: number; entSum: number }>();
  for (const r of perQname) {
    const q = String(r.q).toLowerCase();
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
