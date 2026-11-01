// Neural hunt: an autoencoder over per-host behavioral profiles (Hoelzer's
// "ML shows you where to look"). Trains unsupervised on the population,
// flags hosts the network reconstructs badly - i.e. hosts that don't look
// like the rest - and explains WHICH features pushed them out.
// Runtime: TensorFlow.js (pure JS backend, no Python, no native modules).
import { mkdirSync, readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { styleText } from 'node:util';
import type { DatabaseSync } from 'node:sqlite';
import type { Row } from './store.js';

export const PROFILE_FEATURES = [
  'conns', 'distinct_dst', 'distinct_ports', 'mean_bytes', 'max_bytes_log',
  'dns_share', 'http_share', 'udp_share', 'night_share', 'mean_dur_log',
] as const;

export interface HostProfile {
  ip: string;
  vector: number[];
}

/** One behavioral row per source host - the autoencoder's input population. */
export function extractHostProfiles(db: DatabaseSync, datasetId: number): HostProfile[] {
  const rows = db
    .prepare(
      `SELECT src_ip,
              COUNT(*) AS conns,
              COUNT(DISTINCT dst_ip) AS d_dst,
              COUNT(DISTINCT dst_port) AS d_port,
              AVG(COALESCE(bytes_sent,0) + COALESCE(bytes_recv,0)) AS mean_bytes,
              MAX(COALESCE(bytes_sent,0) + COALESCE(bytes_recv,0)) AS max_bytes,
              AVG(CASE WHEN rcode IS NOT NULL THEN 1.0 ELSE 0.0 END) AS dns_share,
              AVG(CASE WHEN status IS NOT NULL THEN 1.0 ELSE 0.0 END) AS http_share,
              AVG(CASE WHEN proto = 'udp' THEN 1.0 ELSE 0.0 END) AS udp_share,
              AVG(CASE WHEN CAST(strftime('%H', ts / 1000, 'unixepoch') AS INT) >= 22
                     OR CAST(strftime('%H', ts / 1000, 'unixepoch') AS INT) < 6 THEN 1.0 ELSE 0.0 END) AS night_share,
              AVG(CASE WHEN duration_ms IS NOT NULL THEN ln(1 + duration_ms) ELSE NULL END) AS mean_dur
       FROM events WHERE dataset_id = ? AND src_ip IS NOT NULL GROUP BY src_ip`,
    )
    .all(datasetId) as Row[];
  return rows.map((r) => ({
    ip: String(r.src_ip),
    vector: [
      Number(r.conns), Number(r.d_dst), Number(r.d_port), Number(r.mean_bytes),
      Math.log1p(Number(r.max_bytes)), Number(r.dns_share), Number(r.http_share),
      Number(r.udp_share), Number(r.night_share), Number(r.mean_dur ?? 0),
    ],
  }));
}

export function standardizeRows(rows: number[][]): { data: number[][]; means: number[]; stds: number[] } {
  const dims = rows[0].length;
  const means = new Array<number>(dims).fill(0);
  const stds = new Array<number>(dims).fill(1);
  for (const r of rows) for (let d = 0; d < dims; d++) means[d] += r[d];
  for (let d = 0; d < dims; d++) means[d] /= rows.length;
  for (const r of rows) for (let d = 0; d < dims; d++) stds[d] += (r[d] - means[d]) ** 2;
  for (let d = 0; d < dims; d++) {
    stds[d] = Math.sqrt(stds[d] / rows.length);
    if (stds[d] === 0) stds[d] = 1;
  }
  return { data: rows.map((r) => r.map((v, d) => (v - means[d]) / stds[d])), means, stds };
}

interface ModelBundle {
  topology: unknown;
  specs: unknown;
  weights: string; // base64 weightData
  meta: {
    featureNames: string[];
    means: number[];
    stds: number[];
    trainedOn: string;
    hosts: number;
    epochs: number;
    savedAt: string;
  };
}

export interface TrainResult {
  modelPath: string;
  hosts: number;
  epochs: number;
  finalLoss: number;
}

function modelPath(dbPath: string, tenant: string): string {
  const dir = join(dirname(dbPath), 'models');
  mkdirSync(dir, { recursive: true });
  // tenant names are analyst-controlled; strip anything filesystem-hostile anyway
  return join(dir, `${tenant.replace(/[^\w.-]+/g, '_')}.json`);
}

/** tf-backend-cpu prints a node.js banner via console.warn on first use; filter just that. */
async function loadTf(): Promise<typeof import('@tensorflow/tfjs')> {
  const warn = console.warn.bind(console);
  console.warn = (...a: unknown[]) => {
    if (a.some((x) => typeof x === 'string' && x.includes('looks like you are running TensorFlow.js'))) return;
    warn(...a);
  };
  return import('@tensorflow/tfjs');
}

function b64(buf: ArrayBuffer): string {
  return Buffer.from(buf).toString('base64');
}

function unb64(s: string): ArrayBuffer {
  const b = Buffer.from(s, 'base64');
  return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;
}

/**
 * Train the autoencoder on a tenant's host population and persist it next to
 * the database. Deterministic-enough for triage; scores are comparative.
 */
export async function trainAutoencoder(db: DatabaseSync, datasetId: number, dbPath: string, tenant: string, datasetLabel: string, epochs = 60): Promise<TrainResult> {
  const tf = await loadTf();
  const profiles = extractHostProfiles(db, datasetId);
  if (profiles.length < 30) throw new Error(`only ${profiles.length} hosts with source IPs - need at least 30 to train a population model`);
  const { data, means, stds } = standardizeRows(profiles.map((p) => p.vector));
  const dims = data[0].length;
  const xs = tf.tensor2d(data);
  const model = tf.sequential({ layers: [
    tf.layers.dense({ inputShape: [dims], units: 16, activation: 'relu' }),
    tf.layers.dense({ units: 4, activation: 'relu' }),
    tf.layers.dense({ units: 16, activation: 'relu' }),
    tf.layers.dense({ units: dims }), // linear reconstruction
  ] });
  model.compile({ optimizer: tf.train.adam(0.01), loss: 'meanSquaredError' });
  const history = await model.fit(xs, xs, { epochs, batchSize: 32, shuffle: true, verbose: 0 });
  const finalLoss = history.history.loss ? Number(history.history.loss[history.history.loss.length - 1]) : NaN;
  interface SavedArtifacts {
    modelTopology: unknown;
    weightSpecs: unknown;
    weightData: ArrayBuffer;
  }
  const saved = (await model.save(
    tf.io.withSaveHandler(async (a) => ({
      modelArtifactsInfo: { dateSaved: new Date(), modelTopologyType: 'JSON' as const },
      ...a,
    })),
  )) as unknown as SavedArtifacts;
  xs.dispose();
  model.dispose();
  const bundle: ModelBundle = {
    topology: saved.modelTopology,
    specs: saved.weightSpecs,
    weights: b64(saved.weightData as ArrayBuffer),
    meta: {
      featureNames: [...PROFILE_FEATURES],
      means,
      stds,
      trainedOn: datasetLabel,
      hosts: profiles.length,
      epochs,
      savedAt: new Date().toISOString(),
    },
  };
  const p = modelPath(dbPath, tenant);
  writeFileSync(p, JSON.stringify(bundle));
  return { modelPath: p, hosts: profiles.length, epochs, finalLoss };
}

export interface MlFinding {
  ip: string;
  score: number; // mean reconstruction error in z-space (comparative only)
  topDeviations: { feature: string; z: number }[]; // which dims the network got most wrong
}

/** Score every host against the tenant's trained model; worst first. */
export async function scoreHosts(db: DatabaseSync, datasetId: number, dbPath: string, tenant: string, limit = 25): Promise<MlFinding[]> {
  const p = modelPath(dbPath, tenant);
  if (!existsSync(p)) throw new Error(`no trained model for tenant '${tenant}' - run: th ml-train -t ${tenant}`);
  const bundle = JSON.parse(readFileSync(p, 'utf8')) as ModelBundle;
  const tf = await loadTf();
  const model = await tf.loadLayersModel(
    tf.io.fromMemory({ modelTopology: bundle.topology, weightSpecs: bundle.specs, weightData: unb64(bundle.weights) }),
  );
  const profiles = extractHostProfiles(db, datasetId);
  if (!profiles.length) return [];
  const input = profiles.map((pr) => pr.vector.map((v, d) => (v - bundle.meta.means[d]) / bundle.meta.stds[d]));
  const xs = tf.tensor2d(input);
  const out = model.predict(xs) as import('@tensorflow/tfjs').Tensor2D;
  const recon = await out.array();
  xs.dispose();
  out.dispose();
  model.dispose();
  const findings: MlFinding[] = profiles.map((pr, i) => {
    const errs = (recon as number[][])[i].map((r, d) => Math.abs(r - input[i][d]));
    const score = errs.reduce((a, b) => a + b, 0) / errs.length;
    const topDeviations = errs
      .map((e, d) => ({ feature: bundle.meta.featureNames[d], z: input[i][d], e }))
      .sort((a, b) => b.e - a.e)
      .slice(0, 3)
      .map((x) => ({ feature: x.feature, z: Math.round(x.z * 100) / 100 }));
    return { ip: pr.ip, score: Math.round(score * 1000) / 1000, topDeviations };
  });
  findings.sort((a, b) => b.score - a.score);
  return findings.slice(0, limit);
}

export function renderMl(f: MlFinding[], o: { json?: boolean }): void {
  if (o.json) return void console.log(JSON.stringify(f, null, 2));
  console.log(`hosts that fit the population worst (autoencoder reconstruction error):\n`);
  const useColor = process.stdout.isTTY === true && !process.env.NO_COLOR;
  for (let i = 0; i < f.length; i++) {
    const x = f[i];
    const rank = i < 3 && x.score >= (f[0]?.score ?? 0) * 0.5 ? (useColor ? styleText('red', '!!') : '!!') : '  ';
    console.log(`${rank} ${x.ip.padEnd(18)} err ${x.score.toFixed(3)}  ${x.topDeviations.map((d) => `${d.feature}=${d.z}`).join(', ')}`);
  }
}
