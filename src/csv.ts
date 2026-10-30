import { createReadStream } from 'node:fs';
import { parse } from 'csv-parse';

const HOST_COL_NAMES = ['hostname', 'host', 'domain', 'query', 'dns_query', 'dnsquery', 'name', 'fqdn', 'desthostname', 'destinationhostname'];
const COUNT_COL_NAMES = ['count', 'counts', 'queries', 'query_count', 'querycount', 'hits', 'requests', 'request_count', 'total', 'total_queries'];

/** Fold a header name for matching: "COUNT(Matched Events)" and "count_matched_events" both become "countmatchedevents". */
const canonHeader = (s: string): string => s.trim().toLowerCase().replace(/[^a-z0-9]/g, '');

export interface HostRow {
  hostname: string;
  count: number | null;
}

export interface CsvMeta {
  hostKey: string | number;
  countKey: string | number | null;
}

export interface CsvParseOptions {
  noHeader?: boolean;
  hostCol?: string;
  countCol?: string;
}

/** Normalize a hostname for comparison: trim, lowercase, strip trailing root dot. */
export function normalizeHost(raw: string): string {
  let h = raw.trim().toLowerCase();
  while (h.endsWith('.')) h = h.slice(0, -1);
  return h;
}

/**
 * Decide which CSV columns hold the hostname and (optionally) the query count.
 * Works with a header object or a bare array row (--no-header).
 */
export function resolveColumns(record: Record<string, unknown> | unknown[], opts: CsvParseOptions): CsvMeta {
  if (Array.isArray(record)) {
    return { hostKey: 0, countKey: record.length > 1 ? 1 : null };
  }
  const keys = Object.keys(record);
  const canonKeys = keys.map(canonHeader);
  const find = (name: string): number | undefined => {
    const i = canonKeys.indexOf(canonHeader(name));
    return i === -1 ? undefined : i;
  };

  let hostIdx: number | undefined;
  if (opts.hostCol) {
    hostIdx = find(opts.hostCol);
    if (hostIdx === undefined) {
      throw new Error(`column '${opts.hostCol}' not found in CSV header (headers: ${keys.join(', ')})`);
    }
  } else {
    hostIdx = HOST_COL_NAMES.map((n) => find(n)).find((i) => i !== undefined);
    if (hostIdx === undefined && keys.length === 1) hostIdx = 0;
    if (hostIdx === undefined) {
      throw new Error(`could not find a hostname column (headers: ${keys.join(', ')}). Use --host-col <name> to pick one.`);
    }
  }

  let countIdx: number | undefined;
  if (opts.countCol) {
    countIdx = find(opts.countCol);
    if (countIdx === undefined) {
      throw new Error(`column '${opts.countCol}' not found in CSV header (headers: ${keys.join(', ')})`);
    }
  } else {
    countIdx = COUNT_COL_NAMES.map((n) => find(n)).find((i) => i !== undefined);
    // SIEM exports name count columns things like "COUNT(Matched Events)"
    if (countIdx === undefined) {
      const i = canonKeys.findIndex((k) => k.startsWith('count'));
      if (i !== -1) countIdx = i;
    }
  }

  return { hostKey: keys[hostIdx], countKey: countIdx !== undefined ? keys[countIdx] : null };
}

function parseCount(v: unknown): number | null {
  if (v === undefined || v === null || v === '') return null;
  const n = Number(String(v).replace(/[,\s]/g, ''));
  return Number.isFinite(n) && n >= 0 ? n : null;
}

/**
 * Stream a CSV file, calling onHost for every row with a normalized hostname.
 * Memory stays constant regardless of file size.
 */
export async function readHosts(
  file: string,
  opts: CsvParseOptions,
  onHost: (row: HostRow) => void,
): Promise<CsvMeta> {
  const stream = createReadStream(file);
  const parser = stream.pipe(
    parse({
      bom: true,
      trim: true,
      skip_empty_lines: true,
      relax_column_count: true,
      columns: !opts.noHeader,
    }),
  );
  // pipe() does not forward source errors to the destination; forward manually
  // or a missing/unreadable file crashes the process with an unhandled 'error' event
  let streamError: Error | undefined;
  stream.on('error', (err) => {
    streamError = err;
    parser.destroy(err);
  });

  let meta: CsvMeta | null = null;
  try {
    for await (const rawRecord of parser) {
      if (!meta) meta = resolveColumns(rawRecord as Record<string, unknown>, opts);
      const rec = rawRecord as Record<string, unknown> | unknown[];
      const get = (key: string | number): unknown => (typeof key === 'number' ? (rec as unknown[])[key] : (rec as Record<string, unknown>)[key]);
      const hostname = normalizeHost(String(get(meta.hostKey) ?? ''));
      if (!hostname) continue;
      onHost({ hostname, count: meta.countKey === null ? null : parseCount(get(meta.countKey)) });
    }
  } catch (err) {
    throw new Error(`failed to parse ${file}: ${streamError instanceof Error ? streamError.message : err instanceof Error ? err.message : String(err)}`);
  }
  if (!meta) throw new Error(`no rows found in ${file}`);
  return meta;
}
