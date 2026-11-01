// Ensemble hunt: run every detector, merge into one ranked triage queue.
// This is the "use all the tools, look at the combined result" view.
import type { DatabaseSync } from 'node:sqlite';
import { huntBeaconing, huntLongConns, huntVolume, huntDnsTunnel, huntFftBeacons, huntDnsClusters } from './hunts.js';
import { scoreHosts } from './nn.js';

export interface EnsembleRow {
  hunt: string;
  subject: string;
  score: number; // 0-100, detector-native where available, explained otherwise
  detail: string;
}

function longConnScore(hours: number): number {
  if (hours >= 24) return 90;
  if (hours >= 12) return 70;
  if (hours >= 6) return 50;
  if (hours >= 2) return 30;
  return 20;
}

function volumeScore(ratio: number): number {
  if (ratio >= 100) return 90;
  if (ratio >= 30) return 70;
  if (ratio >= 10) return 50;
  if (ratio >= 3) return 30;
  return 15;
}

const pair = (a: string, b: string, port: number | null): string => `${a} -> ${b}${port ? `:${port}` : ''}`;

export async function runEnsemble(db: DatabaseSync, datasetId: number, dbPath: string, tenant: string, limit = 50): Promise<{ rows: EnsembleRow[]; notes: string[] }> {
  const rows: EnsembleRow[] = [];
  const notes: string[] = [];
  for (const b of huntBeaconing(db, datasetId, { limit: 25 })) {
    rows.push({ hunt: 'beaconing', subject: pair(b.src_ip, b.dst_ip, b.dst_port), score: b.score, detail: `${b.conns} conns every ~${Math.round(b.meanIntervalMs / 1000)}s, cv ${b.cv.toFixed(3)}` });
  }
  for (const f of huntFftBeacons(db, datasetId, { limit: 25 })) {
    rows.push({ hunt: 'fft-beacons', subject: pair(f.src_ip, f.dst_ip, f.dst_port), score: f.score, detail: `${f.conns} conns, period ${Math.round(f.periodMs / 1000)}s, ${f.peakRatio}x noise floor` });
  }
  for (const l of huntLongConns(db, datasetId, { limit: 15 })) {
    const h = l.durationMs / 3600000;
    rows.push({ hunt: 'long-conns', subject: pair(l.src_ip, l.dst_ip, l.dst_port), score: longConnScore(h), detail: `open ${h.toFixed(1)}h` });
  }
  for (const v of huntVolume(db, datasetId, { limit: 15 })) {
    rows.push({ hunt: 'volume', subject: v.ip, score: volumeScore(v.medianRatio), detail: `top talker (${v.medianRatio === Infinity ? 'all traffic' : `${v.medianRatio.toFixed(0)}x median`})` });
  }
  for (const d of huntDnsTunnel(db, datasetId, { limit: 15 })) {
    rows.push({ hunt: 'dnstunnel', subject: d.base, score: d.score, detail: `${d.uniqueQnames} unique names, entropy ${d.avgEntropy.toFixed(2)}` });
  }
  for (const c of huntDnsClusters(db, datasetId, { limit: 5 }).clusters) {
    if (c.weirdness < 1.0) continue;
    rows.push({ hunt: 'dns-cluster', subject: c.samples[0] ?? `cluster ${c.cluster}`, score: Math.min(90, Math.round(c.weirdness * 30)), detail: `${c.size} odd names clustered together (e.g. ${c.samples.slice(0, 2).join(', ')})` });
  }
  try {
    const ml = await scoreHosts(db, datasetId, dbPath, tenant, 10);
    const max = ml[0]?.score ?? 0;
    if (max > 0) {
      for (const m of ml) {
        rows.push({ hunt: 'ml-anomaly', subject: m.ip, score: Math.round((m.score / max) * 100), detail: `population outlier: ${m.topDeviations.map((d) => `${d.feature}=${d.z}`).join(', ')}` });
      }
    }
  } catch (e) {
    notes.push(`ml-anomaly skipped (${e instanceof Error ? e.message : String(e)})`);
  }
  rows.sort((a, b) => b.score - a.score);
  return { rows: rows.slice(0, limit), notes };
}
