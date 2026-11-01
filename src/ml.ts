// The math behind the ML hunts: FFT, DBSCAN, PCA, standardization, qname
// features. Pure TypeScript, no dependencies - these are Hoelzer-style
// "show me where to look" primitives, not verdict machines.

export function nextPow2(n: number): number {
  let p = 1;
  while (p < n) p <<= 1;
  return p;
}

/**
 * Iterative radix-2 Cooley-Tukey FFT; zero-pads to a power of two and returns
 * magnitudes for bins 0..n/2 of the real input signal. Bin k corresponds to
 * frequency k / (n * binWidth); bin 0 is the DC offset (ignore it).
 */
export function fftMagnitudes(signal: number[]): number[] {
  const n = nextPow2(signal.length);
  const re = new Float64Array(n);
  for (let i = 0; i < signal.length; i++) re[i] = signal[i];
  const im = new Float64Array(n);
  for (let i = 1, j = 0; i < n; i++) {
    let bit = n >> 1;
    for (; j & bit; bit >>= 1) j ^= bit;
    j ^= bit;
    if (i < j) {
      const tr = re[i]; re[i] = re[j]; re[j] = tr;
      const ti = im[i]; im[i] = im[j]; im[j] = ti;
    }
  }
  for (let len = 2; len <= n; len <<= 1) {
    const ang = (-2 * Math.PI) / len;
    const wRe = Math.cos(ang);
    const wIm = Math.sin(ang);
    for (let i = 0; i < n; i += len) {
      let curRe = 1;
      let curIm = 0;
      for (let k = 0; k < len / 2; k++) {
        const uRe = re[i + k];
        const uIm = im[i + k];
        const vRe = re[i + k + len / 2] * curRe - im[i + k + len / 2] * curIm;
        const vIm = re[i + k + len / 2] * curIm + im[i + k + len / 2] * curRe;
        re[i + k] = uRe + vRe;
        im[i + k] = uIm + vIm;
        re[i + k + len / 2] = uRe - vRe;
        im[i + k + len / 2] = uIm - vIm;
        const nRe = curRe * wRe - curIm * wIm;
        curIm = curRe * wIm + curIm * wRe;
        curRe = nRe;
      }
    }
  }
  const mags: number[] = [];
  for (let k = 0; k <= n / 2; k++) mags.push(Math.hypot(re[k], im[k]));
  return mags;
}

/** z-score every dimension over the population; constant dims collapse to 0. */
export function standardize(rows: number[][]): { data: number[][]; means: number[]; stds: number[] } {
  const dims = rows[0].length;
  const means = new Array<number>(dims).fill(0);
  const stds = new Array<number>(dims).fill(0);
  for (const r of rows) for (let d = 0; d < dims; d++) means[d] += r[d];
  for (let d = 0; d < dims; d++) means[d] /= rows.length;
  for (const r of rows) for (let d = 0; d < dims; d++) stds[d] += (r[d] - means[d]) ** 2;
  for (let d = 0; d < dims; d++) stds[d] = Math.sqrt(stds[d] / rows.length) || 1;
  const data = rows.map((r) => r.map((v, d) => (v - means[d]) / stds[d]));
  return { data, means, stds };
}

function dist2(a: number[], b: number[]): number {
  let s = 0;
  for (let i = 0; i < a.length; i++) s += (a[i] - b[i]) ** 2;
  return s;
}

/**
 * DBSCAN density clustering. Returns a cluster id per point; -1 = noise
 * (outlier), -2 = unreachable edge case. O(n^2) - cap the input for huge
 * populations (the hunt samples before calling this).
 */
export function dbscan(points: number[][], eps: number, minPts: number): number[] {
  const n = points.length;
  const labels = new Array<number>(n).fill(-2);
  const eps2 = eps * eps;
  const region = (i: number): number[] => {
    const out: number[] = [];
    for (let j = 0; j < n; j++) if (dist2(points[i], points[j]) <= eps2) out.push(j);
    return out;
  };
  let cid = 0;
  for (let i = 0; i < n; i++) {
    if (labels[i] !== -2) continue;
    const neigh = region(i);
    if (neigh.length < minPts) {
      labels[i] = -1; // noise for now; may be claimed by a cluster below
      continue;
    }
    labels[i] = cid;
    const queue = [...neigh];
    for (let q = 0; q < queue.length; q++) {
      const j = queue[q];
      if (labels[j] === -1) labels[j] = cid; // noise -> border point
      if (labels[j] !== -2) continue;
      labels[j] = cid;
      const jn = region(j);
      if (jn.length >= minPts) for (const k of jn) if (labels[k] === -2 || labels[k] === -1) queue.push(k);
    }
    cid++;
  }
  return labels;
}

/**
 * Top-2 principal components via covariance-matrix power iteration with
 * deflation. Input is expected standardized; explained values are fractions
 * of total variance (trace = dims).
 */
export function pca2(data: number[][]): { proj: { x: number; y: number }[]; explained: [number, number] } {
  const dims = data[0].length;
  const n = data.length;
  const cov = (a: number[], b: number[]): number => {
    let s = 0;
    for (let i = 0; i < n; i++) s += a[i] * b[i];
    return s / n;
  };
  const col = (d: number): number[] => data.map((r) => r[d]);
  const cols: number[][] = [];
  for (let d = 0; d < dims; d++) cols.push(col(d));
  // Build the covariance matrix C (dims x dims) once.
  const C: number[][] = [];
  for (let a = 0; a < dims; a++) {
    C.push([]);
    for (let b = 0; b < dims; b++) C[a].push(cov(cols[a], cols[b]));
  }
  const vecs: number[][] = [];
  const vals: number[] = [];
  for (let c = 0; c < 2; c++) {
    let v: number[] = new Array<number>(dims).fill(0).map((_, i) => (i === c ? 1 : 0.5));
    for (let iter = 0; iter < 128; iter++) {
      const next = new Array<number>(dims).fill(0);
      for (let d = 0; d < dims; d++) for (let e = 0; e < dims; e++) next[d] += C[d][e] * v[e];
      const norm = Math.hypot(...next) || 1;
      v = next.map((x) => x / norm);
    }
    // Rayleigh quotient = variance captured
    let eig = 0;
    for (let d = 0; d < dims; d++) for (let e = 0; e < dims; e++) eig += v[d] * C[d][e] * v[e];
    vecs.push(v);
    vals.push(eig);
    // deflation: C := C - eig * v v^T
    for (let d = 0; d < dims; d++) for (let e = 0; e < dims; e++) C[d][e] -= eig * v[d] * v[e];
  }
  const proj = data.map((r) => ({
    x: r.reduce((a, x, d) => a + x * vecs[0][d], 0),
    y: r.reduce((a, x, d) => a + x * vecs[1][d], 0),
  }));
  const explained: [number, number] = [
    Math.max(0, vals[0] / dims),
    Math.max(0, vals[1] / dims),
  ];
  return { proj, explained };
}

// ---------- qname features ----------

/** Rough english-bigram familiarity: share of bigrams found in common words. */
const COMMON_BIGRAMS = new Set(
  ('th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc et ut ss so rs un lo wa ge ie co wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai sh ir su id os iv ia am fi ci vi pl ig tu ev ld ry ca pe al ab').match(/(..)/g) ?? [],
);

export interface QnameFeatures {
  qname: string;
  length: number;
  labels: number;
  maxLabel: number;
  entropy: number;
  digitRatio: number;
  rarity: number; // share of bigrams absent from COMMON_BIGRAMS
}

export function qnameFeatures(q: string): QnameFeatures {
  const s = q.replace(/\.$/, '').toLowerCase();
  const parts = s.split('.');
  const maxLabel = Math.max(...parts.map((p) => p.length));
  let digits = 0;
  let bigrams = 0;
  let rare = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] >= '0' && s[i] <= '9') digits++;
    if (i + 1 < s.length) {
      bigrams++;
      const bg = s.slice(i, i + 2);
      if (!COMMON_BIGRAMS.has(bg)) rare++;
    }
  }
  return {
    qname: s,
    length: s.length,
    labels: parts.length,
    maxLabel,
    entropy: entropy(s),
    digitRatio: s.length ? digits / s.length : 0,
    rarity: bigrams ? rare / bigrams : 1,
  };
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
