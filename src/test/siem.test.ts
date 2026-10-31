import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseFortiKv, parseIisRaw, readSiem } from '../siem.js';
import type { EventRow } from '../store.js';

// sanitized FortiOS lines in the exact shape of real exports
const FORTI_TRAFFIC =
  '<188>date=2026-10-31 time=20:14:00 devname="FGT-example-Active" devid="FG5H0E5819902918" eventtime=1793465034986126239 tz="+0330" logid="0000000007" type="traffic" subtype="forward" level="warning" vd="root" srcip=172.20.21.40 srcname="172.20.21.40" srcport=42050 srcintf="To-Folad" srcintfrole="undefined" dstip=194.225.150.25 dstname="ir.pool.ntp.org" dstport=123 dstintf="port5" dstintfrole="wan" srccountry="Reserved" dstcountry="Iran, Islamic Republic of" sessionid=244822547 proto=17 action="deny" policyid=0 policytype="policy" service="NTP" trandisp="noop" duration=0 sentbyte=0 rcvdbyte=0 sentpkt=0 rcvdpkt=0 msg="Denied by forward policy check (policy 0)"';

const FORTI_DNS_BROKEN_QUOTE =
  '<190>date=2026-10-31 time=20:14:38 devname="FGT-example-Active" devid="FG5H0E5819902918" eventtime=1793465078221852380 tz="+0330" logid="1501054805" type="utm" subtype="dns" eventtype="dns-response" level="information" vd="root" policyid=0 sessionid=0 user=" dstuser=" srcport=0 srcintf="unknown-0" srcintfrole="undefined" dstip=192.168.1.1 dstport=53 dstcountry="Reserved" dstintf="unknown-0" dstintfrole="undefined" proto=17 xid=980 qname="3.91.20.10.in-addr.arpa" qtype="PTR" qtypeval=12 qclass="IN" action="pass"';

const IIS_LINE =
  ' <13>Oct 31 18:28:29 WSUS IISWebLog 2026-10-31 14:57:47 W3SVC1343212632 WSUS fe80::e19a:152f:d123:fd80%15 POST /ApiRemoting30/WebService.asmx - 8530 WSUS\\Administrator fe80::e19a:152f:d123:fd80%15 HTTP/1.1 Mozilla/4.0+(compatible;+MSIE+6.0;+MS+Web+Services+Client+Protocol+4.0.30319.42000) - - wsus:8530 200 0 0 711 1371 7';

test('parseFortiKv maps traffic logs: ips, ports, proto, duration, bytes, timestamp with tz', () => {
  const e = parseFortiKv(FORTI_TRAFFIC);
  assert.ok(e);
  assert.equal(e.src_ip, '172.20.21.40');
  assert.equal(e.src_port, 42050);
  assert.equal(e.dst_ip, '194.225.150.25');
  assert.equal(e.dst_port, 123);
  assert.equal(e.proto, 'udp');
  assert.equal(e.duration_ms, 0);
  assert.equal(e.bytes_sent, 0);
  assert.equal(e.bytes_recv, 0);
  // 2026-10-31 20:14:00 +03:30 == 16:44:00 UTC
  assert.equal(e.ts, Date.parse('2026-10-31T20:14:00+03:30'));
});

test('parseFortiKv maps utm/dns logs and survives a broken user= quote', () => {
  const e = parseFortiKv(FORTI_DNS_BROKEN_QUOTE);
  assert.ok(e);
  assert.equal(e.dst_host, '3.91.20.10.in-addr.arpa');
  assert.equal(e.qtype, 'PTR');
  assert.equal(e.proto, 'udp');
  assert.equal(e.dst_ip, '192.168.1.1');
  assert.equal(e.dst_port, 53);
});

test('parseFortiKv rejects unsupported types and traffic rows without ips', () => {
  assert.equal(parseFortiKv('type="utm" subtype="webfilter" msg="blocked"'), null);
  assert.equal(parseFortiKv('type="event" subtype="system"'), null);
  assert.equal(parseFortiKv('type="traffic" srcip=1.2.3.4'), null); // no dstip
});

test('parseIisRaw maps standard W3C fields by position', () => {
  const e = parseIisRaw(IIS_LINE);
  assert.ok(e);
  assert.equal(e.method, 'POST');
  assert.equal(e.uri, '/ApiRemoting30/WebService.asmx');
  assert.equal(e.status, 200);
  assert.equal(e.dst_host, 'wsus'); // cs-host wsus:8530, port stripped
  assert.equal(e.src_ip, 'fe80::e19a:152f:d123:fd80%15');
  assert.equal(e.dst_port, 8530);
  assert.equal(e.user_agent, 'Mozilla/4.0+(compatible;+MSIE+6.0;+MS+Web+Services+Client+Protocol+4.0.30319.42000)');
  assert.equal(e.bytes_sent, 1371); // cs-bytes
  assert.equal(e.bytes_recv, 711); // sc-bytes
  assert.equal(e.duration_ms, 7000); // time-taken is seconds
  assert.ok(e.ts !== null);
});

test('parseIisRaw rejects lines without the marker or with too few fields', () => {
  assert.equal(parseIisRaw('some random syslog line'), null);
  const short = IIS_LINE.slice(0, IIS_LINE.indexOf('HTTP/1.1'));
  assert.equal(parseIisRaw(short), null);
});

test('readSiem streams a wrapper csv, auto-detects fortinet vs iis, counts skips', async () => {
  const rows: EventRow[] = [];
  const wrapper = [
    '"Event Source","Event Type","Raw Event Log",',
    '" FortinetOS"," FortiOS Traffic","' + FORTI_TRAFFIC.replace(/"/g, '""') + '",',
    '" IIS"," Web request successful","' + IIS_LINE.replace(/"/g, '""').trim() + '",',
    '" X"," Unknown thing","<13>Oct 31 18:00:00 host weirdlog nothing=useful",',
  ].join('\r\n');
  const dir = mkdtempSync(join(tmpdir(), 'th-siem-'));
  try {
    const file = join(dir, 'wrapper.csv');
    writeFileSync(file, wrapper, 'utf8');
    const res = await readSiem(file, (e) => rows.push(e));
    assert.equal(res.fortinet, 1);
    assert.equal(res.iis, 1);
    assert.equal(res.skipped, 1); // unknown raw line produced no event
    assert.equal(res.rows, 2);
    assert.equal(rows.length, 2);
  } finally {
    rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
  }
});

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
