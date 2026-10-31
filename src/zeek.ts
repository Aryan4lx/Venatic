import { createReadStream, type Dirent } from 'node:fs';
import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { createGunzip } from 'node:zlib';
import { createInterface } from 'node:readline';
import type { EventRow } from './store.js';

const num = (v?: string): number | null => {
  if (v === undefined) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};
const str = (v?: string): string | null => (v === undefined ? null : v);

/** Zeek writes separators as "\x09" escapes in the #separator directive. */
function unescapeZeek(s: string): string {
  return s.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

interface ZeekHeader {
  path: string; // zeek log type: conn, dns, http, ...
  fields: string[];
  sep: string;
  empty: string;
  unset: string;
}

async function* zeekRecords(file: string): AsyncGenerator<{ header: ZeekHeader; data: string[] }> {
  const stream = createReadStream(file);
  const input = file.toLowerCase().endsWith('.gz') ? stream.pipe(createGunzip()) : stream;
  const rl = createInterface({ input, crlfDelay: Infinity });
  const header: ZeekHeader = { path: '', fields: [], sep: '\t', empty: '(empty)', unset: '-' };
  // fallback: infer log type from filename (conn.log, dns.log.gz, http@...log)
  const base = file.split(/[\\/]/).pop() ?? '';
  header.path = base.replace(/\.log(\.gz)?$/i, '').replace(/@.*$/, '');
  try {
    for await (const line of rl) {
      if (line.startsWith('#')) {
        // zeek delimits directive names with a space (only #separator) or the
        // separator char itself (#path, #fields, ...)
        const rest = line.slice(1);
        const sepIdx = rest.indexOf(header.sep);
        const spIdx = rest.indexOf(' ');
        const end = sepIdx === -1 ? spIdx : spIdx === -1 ? sepIdx : Math.min(sepIdx, spIdx);
        if (end === -1) continue;
        const key = rest.slice(0, end);
        const val = rest.slice(end + 1);
        if (key === 'separator') header.sep = unescapeZeek(val);
        else if (key === 'path') header.path = val.trim();
        else if (key === 'empty_field') header.empty = unescapeZeek(val);
        else if (key === 'unset_field') header.unset = unescapeZeek(val);
        else if (key === 'fields') header.fields = val.split(header.sep);
        continue;
      }
      if (!header.fields.length) continue;
      yield { header, data: line.split(header.sep) };
    }
  } finally {
    if (input !== stream) input.destroy();
    stream.destroy();
  }
}

function mapEvent(h: ZeekHeader, data: string[]): EventRow | null {
  const get = (f: string): string | undefined => {
    const i = h.fields.indexOf(f);
    if (i === -1) return undefined;
    const v = data[i] ?? '';
    return v === h.unset || v === h.empty || v === '' ? undefined : v;
  };
  const ms = (f: string): number | null => {
    const s = num(get(f));
    return s === null ? null : Math.round(s * 1000);
  };
  const row: EventRow = {};
  switch (h.path) {
    case 'conn':
      row.ts = ms('ts');
      row.src_ip = str(get('id.orig_h'));
      row.src_port = num(get('id.orig_p'));
      row.dst_ip = str(get('id.resp_h'));
      row.dst_port = num(get('id.resp_p'));
      row.proto = str(get('proto'));
      row.duration_ms = ms('duration');
      row.bytes_sent = num(get('orig_bytes'));
      row.bytes_recv = num(get('resp_bytes'));
      return row.src_ip && row.dst_ip ? row : null;
    case 'dns':
      row.ts = ms('ts');
      row.src_ip = str(get('id.orig_h'));
      row.dst_ip = str(get('id.resp_h'));
      row.dst_port = num(get('id.resp_p'));
      row.proto = str(get('proto'));
      row.dst_host = str(get('query'))?.replace(/\.$/, '');
      row.rcode = str(get('rcode_name'));
      row.qtype = str(get('qtype_name'));
      return row.dst_host ? row : null;
    case 'http':
      row.ts = ms('ts');
      row.src_ip = str(get('id.orig_h'));
      row.dst_ip = str(get('id.resp_h'));
      row.dst_port = num(get('id.resp_p'));
      row.dst_host = str(get('host'))?.replace(/:\d+$/, '');
      row.method = str(get('method'));
      row.uri = str(get('uri'));
      row.status = num(get('status_code'));
      row.user_agent = str(get('user_agent'));
      row.bytes_sent = num(get('request_body_len'));
      row.bytes_recv = num(get('response_body_len'));
      return row.src_ip ? row : null;
    default:
      return null; // ssl, weird, files, ... - unsupported for now
  }
}

export interface ZeekFileResult {
  file: string;
  kind: string; // conn | dns | http | <skipped type>
  rows: number;
}

/** Stream one Zeek log file (TSV or .gz), calling onEvent for every mapped row. */
export async function readZeekLog(file: string, onEvent: (e: EventRow) => void): Promise<ZeekFileResult> {
  let kind = '';
  let rows = 0;
  for await (const { header, data } of zeekRecords(file)) {
    kind = header.path;
    const e = mapEvent(header, data);
    if (e) {
      onEvent(e);
      rows++;
    }
  }
  return { file, kind: kind || 'unknown', rows };
}

async function walkLogFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  const entries: Dirent[] = await readdir(dir, { withFileTypes: true });
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...(await walkLogFiles(p)));
    else if (/\.log(\.gz)?$/i.test(e.name)) out.push(p);
  }
  return out.sort();
}

/**
 * Read a Zeek log file or a directory of them (recursively), calling onEvent
 * for every mapped row. Returns per-file summaries.
 */
export async function readZeek(target: string, onEvent: (e: EventRow) => void): Promise<ZeekFileResult[]> {
  const st = await stat(target);
  const files = st.isDirectory() ? await walkLogFiles(target) : [target];
  const results: ZeekFileResult[] = [];
  for (const f of files) results.push(await readZeekLog(f, onEvent));
  return results;
}
