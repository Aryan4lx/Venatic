// Local web dashboard: thin JSON API over the exact engine the CLI uses.
// Binds 127.0.0.1 only - this is a workstation tool, not a network service.
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFileSync, existsSync } from 'node:fs';
import { exec } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  openDb, listTenants, listDatasets, getDataset, latestDataset, diffCounts,
  iterAdded, iterRemoved, iterChanged,
  type Dataset,
} from '../store.js';
import { huntBeaconing, huntLongConns, huntVolume, huntDnsTunnel } from '../hunts.js';
import { resolveDbPath } from '../config.js';

export interface ServeOpts {
  db?: string;
  port?: number;
  open?: boolean;
}

const HERE = dirname(fileURLToPath(import.meta.url));

function asset(name: string): string {
  // server.ts sits inside web/ both in src (tsx) and dist; under tsx fall back to
  // node_modules for the chart lib since src/web has no copied assets
  const p = join(HERE, name);
  if (existsSync(p)) return p;
  if (name === 'chart.umd.js') return createRequire(import.meta.url).resolve('chart.js');
  return p;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const buf = Buffer.from(JSON.stringify(body));
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': buf.length });
  res.end(buf);
}

function sendFile(res: ServerResponse, path: string, type: string): void {
  try {
    const buf = readFileSync(path);
    res.writeHead(200, { 'content-type': type, 'content-length': buf.length });
    res.end(buf);
  } catch (err) {
    sendJson(res, 500, { error: `cannot read ${path}: ${err instanceof Error ? err.message : String(err)}` });
  }
}

/** diff rows are capped so a multi-million-row diff cannot blow up the browser */
const SECTION_CAP = 5000;

interface DiffPayload {
  baseline: { label: string; imported_at: string; row_count: number };
  incoming: { label: string; imported_at: string; row_count: number };
  counts: { added: number; removed: number; changed: number; unchanged: number };
  added: { hostname: string; count: number | null }[];
  removed: { hostname: string; count: number | null }[];
  changed: { hostname: string; oldCount: number; newCount: number; delta: number }[];
}

function diffPayload(db: Parameters<typeof listTenants>[0], baseline: Dataset, incoming: Dataset): DiffPayload {
  const counts = diffCounts(db, baseline.id, incoming.id);
  const take = <T>(iter: IterableIterator<T>, score: (x: T) => number): T[] =>
    Array.from(iter).sort((a, b) => score(b) - score(a)).slice(0, SECTION_CAP);
  const added = take(iterAdded(db, baseline.id, incoming.id), (x) => x.count ?? 0);
  const removed = take(iterRemoved(db, baseline.id, incoming.id), (x) => x.count ?? 0);
  const changed = take(iterChanged(db, baseline.id, incoming.id), (x) => Math.abs(x.newCount - x.oldCount)).map((x) => ({
    hostname: x.hostname,
    oldCount: x.oldCount,
    newCount: x.newCount,
    delta: x.newCount - x.oldCount,
  }));
  return {
    baseline: { label: baseline.label, imported_at: baseline.imported_at, row_count: baseline.row_count },
    incoming: { label: incoming.label, imported_at: incoming.imported_at, row_count: incoming.row_count },
    counts,
    added,
    removed,
    changed,
  };
}

const HUNT_NAMES = ['beaconing', 'long-conns', 'volume', 'dnstunnel'] as const;

function huntPayload(db: Parameters<typeof listTenants>[0], tenant: string, q: URLSearchParams): unknown {
  const name = q.get('name') ?? '';
  if (!(HUNT_NAMES as readonly string[]).includes(name)) {
    throw new Error(`unknown hunt '${name}' (one of: ${HUNT_NAMES.join(', ')})`);
  }
  const label = q.get('label');
  const ds = label ? getDataset(db, tenant, label) : latestDataset(db, tenant, 'events');
  if (!ds) throw new Error(label ? `no dataset '${label}' for tenant '${tenant}'` : `no events dataset for tenant '${tenant}'`);
  const num = (k: string): number | undefined => {
    const v = q.get(k);
    if (v === null || v === '') return undefined;
    const n = Number(v);
    if (!Number.isFinite(n) || n < 0) throw new Error(`invalid ${k}: '${v}'`);
    return n;
  };
  let findings: unknown[];
  switch (name) {
    case 'beaconing':
      findings = huntBeaconing(db, ds.id, { minConns: num('min-conns'), maxCv: num('max-cv'), minIntervalMs: num('min-interval'), limit: num('limit') });
      break;
    case 'long-conns':
      findings = huntLongConns(db, ds.id, { minDurationMs: num('min-duration'), limit: num('limit') });
      break;
    case 'volume':
      findings = huntVolume(db, ds.id, { by: q.get('by') === 'dst' ? 'dst' : 'src', limit: num('limit') }).map((x) => ({
        ...x,
        // JSON has no Infinity; null = "any traffic at all" (median was 0)
        medianRatio: Number.isFinite(x.medianRatio) ? x.medianRatio : null,
      }));
      break;
    default: // 'dnstunnel' - name was validated above
      findings = huntDnsTunnel(db, ds.id, { minConns: num('min-conns'), limit: num('limit') });
  }
  return { dataset: { label: ds.label, imported_at: ds.imported_at, row_count: ds.row_count }, findings };
}

export async function startServe(o: ServeOpts = {}): Promise<{ port: number; close(): void; url: string }> {
  const db = openDb(resolveDbPath(o.db));
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    try {
      switch (true) {
        case url.pathname === '/':
          return sendFile(res, asset('app.html'), 'text/html; charset=utf-8');
        case url.pathname === '/chart.umd.js':
          return sendFile(res, asset('chart.umd.js'), 'text/javascript; charset=utf-8');
        case url.pathname === '/api/tenants':
          return sendJson(res, 200, listTenants(db));
        case url.pathname === '/api/datasets':
          return sendJson(res, 200, listDatasets(db, url.searchParams.get('tenant') ?? undefined));
        case url.pathname === '/api/diff': {
          const tenant = url.searchParams.get('tenant');
          if (!tenant) throw new Error('tenant is required');
          const fromLabel = url.searchParams.get('from');
          if (!fromLabel) throw new Error('from is required');
          const from = getDataset(db, tenant, fromLabel);
          if (!from) throw new Error(`no dataset '${fromLabel}' for tenant '${tenant}'`);
          const toLabel = url.searchParams.get('to');
          const to = toLabel ? getDataset(db, tenant, toLabel) : latestDataset(db, tenant, from.kind);
          if (!to) throw new Error(toLabel ? `no dataset '${toLabel}' for tenant '${tenant}'` : 'no incoming dataset');
          return sendJson(res, 200, diffPayload(db, from, to));
        }
        case url.pathname === '/api/hunt': {
          const tenant = url.searchParams.get('tenant');
          if (!tenant) throw new Error('tenant is required');
          return sendJson(res, 200, huntPayload(db, tenant, url.searchParams));
        }
        default:
          return sendJson(res, 404, { error: 'not found' });
      }
    } catch (err) {
      return sendJson(res, 400, { error: err instanceof Error ? err.message : String(err) });
    }
  });
  const requested = o.port ?? 8422;
  await new Promise<void>((res, rej) => {
    server.once('listening', res);
    server.once('error', rej);
    server.listen(requested, '127.0.0.1');
  });
  const port = (server.address() as AddressInfo).port; // port 0 -> actual ephemeral port
  const url = `http://127.0.0.1:${port}`;
  const close = (): void => {
    server.close();
    db.close();
  };
  if (o.open !== false) {
    const cmd = process.platform === 'win32' ? `start "" "${url}"` : process.platform === 'darwin' ? `open "${url}"` : `xdg-open "${url}"`;
    exec(cmd, () => {});
  }
  return { port, close, url };
}
