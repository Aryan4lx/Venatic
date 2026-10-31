import { createReadStream } from 'node:fs';
import { parse } from 'csv-parse';
import { normalizeHost } from './csv.js';
import type { EventRow } from './store.js';

const PROTO_NAMES: Record<number, string> = { 1: 'icmp', 6: 'tcp', 17: 'udp' };

const num = (v: string | undefined): number | null => {
  if (v === undefined) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
};
const protoName = (v: string | undefined): string | null => {
  const n = num(v);
  if (n === null) return null;
  return PROTO_NAMES[n] ?? `proto-${n}`;
};

/** FortiOS date/time/tz (+0330 style) to epoch ms; falls back to eventtime nanoseconds. */
function fortiosTs(kv: Record<string, string>): number | null {
  const date = kv['date'];
  const time = kv['time'];
  if (date && time) {
    const tz = (kv['tz'] ?? '+0000').replace(/^([+-]\d{2})(\d{2})$/, '$1:$2');
    const ms = Date.parse(`${date}T${time}${tz}`);
    if (Number.isFinite(ms)) return ms;
  }
  const et = num(kv['eventtime']);
  return et !== null && et > 1e15 ? Math.round(et / 1e6) : null; // eventtime is nanoseconds
}

/**
 * Parse one FortiOS key=value raw log line (traffic or utm/dns subtypes).
 * Survives broken quoting like user=" dstuser=" - the malformed pair is
 * swallowed and parsing continues.
 */
export function parseFortiKv(raw: string): EventRow | null {
  const kv: Record<string, string> = {};
  const re = /([a-zA-Z0-9_]+)=("(?:[^"]*)"|\S*)/g;
  for (let m = re.exec(raw); m; m = re.exec(raw)) {
    let v = m[2];
    if (v.length >= 2 && v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    kv[m[1]] = v;
  }
  const type = kv['type'];
  if (type === 'utm' && kv['subtype'] === 'dns') {
    const qname = kv['qname'] ? normalizeHost(kv['qname']) : '';
    if (!qname) return null;
    return {
      ts: fortiosTs(kv),
      src_ip: kv['srcip'] ?? null,
      src_port: num(kv['srcport']),
      dst_ip: kv['dstip'] ?? null,
      dst_port: num(kv['dstport']),
      proto: protoName(kv['proto']),
      dst_host: qname,
      rcode: kv['rcode'] ?? null,
      qtype: kv['qtype'] ?? null,
    };
  }
  if (type === 'traffic') {
    if (!kv['srcip'] || !kv['dstip']) return null;
    const dur = num(kv['duration']);
    return {
      ts: fortiosTs(kv),
      src_ip: kv['srcip'],
      src_port: num(kv['srcport']),
      dst_ip: kv['dstip'],
      dst_port: num(kv['dstport']),
      proto: protoName(kv['proto']),
      duration_ms: dur !== null ? dur * 1000 : null,
      bytes_sent: num(kv['sentbyte']),
      bytes_recv: num(kv['rcvdbyte']),
    };
  }
  return null; // utm/webfilter, utm/virus, event, ... - unsupported for now
}

/**
 * Parse one IIS log line from a syslog wrapper: "<13>... WSUS IISWebLog <w3c line>".
 * shortcut: assumes the standard W3C field order (date time s-sitename ... cs-host
 * sc-status sc-substatus sc-win32-status sc-bytes cs-bytes time-taken); a site with
 * non-standard extra fields in the middle would mis-map. Upgrade when seen.
 */
export function parseIisRaw(raw: string): EventRow | null {
  const marker = raw.indexOf('IISWebLog');
  if (marker === -1) return null;
  const fields = raw.slice(marker + 'IISWebLog'.length).trim().split(/\s+/);
  if (fields.length < 22) return null;
  const val = (i: number): string | null => (fields[i] === '-' ? null : fields[i]);
  const ms = Date.parse(`${fields[0]}T${fields[1]}`); // W3C has no tz - parsed as venatic-host local time
  const taken = num(fields[21]);
  let host = val(15);
  if (host) {
    host = host.replace(/:\d+$/, '').toLowerCase();
  } else {
    host = val(4) ? (val(4) as string).toLowerCase() : null;
  }
  return {
    ts: Number.isFinite(ms) ? ms : null,
    src_ip: val(10),
    dst_ip: val(4),
    dst_port: num(fields[8]),
    dst_host: host,
    method: val(5),
    uri: val(6),
    status: num(fields[16]),
    user_agent: val(12),
    bytes_recv: num(fields[19]), // sc-bytes: server sent to client
    bytes_sent: num(fields[20]), // cs-bytes: client sent to server
    duration_ms: taken !== null ? Math.round(taken * 1000) : null,
  };
}

export interface SiemResult {
  rows: number; // mapped events
  fortinet: number;
  iis: number;
  skipped: number; // rows with unsupported/empty raw logs
}

/**
 * Stream a SIEM CSV export where each row carries the original log line in a
 * "Raw Event Log" column (FortiOS and IIS W3C supported, auto-detected per row).
 */
export async function readSiem(file: string, onEvent: (e: EventRow) => void): Promise<SiemResult> {
  const stream = createReadStream(file);
  const parser = stream.pipe(
    parse({ bom: true, trim: true, skip_empty_lines: true, columns: true, relax_column_count: true }),
  );
  let streamError: Error | undefined;
  stream.on('error', (err) => {
    streamError = err;
    parser.destroy(err);
  });
  const res: SiemResult = { rows: 0, fortinet: 0, iis: 0, skipped: 0 };
  try {
    for await (const rec of parser) {
      const get = (canon: string): string | undefined =>
        Object.keys(rec as Record<string, unknown>).find((k) => k.toLowerCase().replace(/[^a-z0-9]/g, '') === canon) as string | undefined;
      const raw = String(rec[get('raweventlog') as never] ?? '').trim();
      if (!raw) {
        res.skipped++;
        continue;
      }
      const isIis = raw.includes('IISWebLog');
      const e = isIis ? parseIisRaw(raw) : parseFortiKv(raw);
      if (e) {
        onEvent(e);
        res.rows++;
        if (isIis) res.iis++;
        else res.fortinet++;
      } else {
        res.skipped++;
      }
    }
  } catch (err) {
    throw new Error(`failed to parse ${file}: ${streamError instanceof Error ? streamError.message : err instanceof Error ? err.message : String(err)}`);
  }
  return res;
}
