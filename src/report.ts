import { styleText } from 'node:util';
import type { DatabaseSync } from 'node:sqlite';
import { iterAdded, iterChanged, iterRemoved, type Dataset, type DiffCounts } from './store.js';

const useColor = process.stdout.isTTY === true && !process.env.NO_COLOR;
const c = (color: 'green' | 'red' | 'yellow' | 'gray', s: string): string => (useColor ? styleText(color, s) : s);

function printSection(
  title: string,
  color: 'green' | 'red' | 'yellow',
  total: number,
  rows: Iterable<{ hostname: string; count?: number | null; oldCount?: number; newCount?: number }>,
  limit: number,
  fmt: (row: { hostname: string; count?: number | null; oldCount?: number; newCount?: number }) => string,
): void {
  console.log(c(color, `${title} (${total})`));
  let shown = 0;
  for (const row of rows) {
    if (shown >= limit) break;
    console.log('  ' + fmt(row));
    shown++;
  }
  if (total > shown) {
    console.log(c('gray', `  ... and ${total - shown} more (raise --limit, or use --json / --csv for the full list)`));
  }
  console.log('');
}

export function renderDiffTerminal(
  db: DatabaseSync,
  baseline: Dataset,
  incoming: Dataset,
  counts: DiffCounts,
  limit: number,
): void {
  console.log('');
  console.log(`tenant:   ${baseline.tenant}`);
  console.log(`baseline: ${baseline.label}  (imported ${baseline.imported_at}, ${baseline.row_count} hostnames)`);
  console.log(`incoming: ${incoming.label}  (${incoming.row_count} hostnames)`);
  console.log('');
  console.log(
    [
      c('green', `NEW ${counts.added}`),
      c('red', `REMOVED ${counts.removed}`),
      c('yellow', `CHANGED ${counts.changed}`),
      c('gray', `UNCHANGED ${counts.unchanged}`),
    ].join('  |  '),
  );
  console.log('');

  const countLabel = (v: number | null | undefined): string => (v === null || v === undefined ? '' : `  count ${v}`);
  if (counts.added > 0) {
    printSection('NEW hostnames', 'green', counts.added, iterAdded(db, baseline.id, incoming.id), limit, (r) => r.hostname.padEnd(36) + c('gray', countLabel(r.count)));
  }
  if (counts.removed > 0) {
    printSection('REMOVED hostnames', 'red', counts.removed, iterRemoved(db, baseline.id, incoming.id), limit, (r) => r.hostname.padEnd(36) + c('gray', countLabel(r.count)));
  }
  if (counts.changed > 0) {
    printSection('CHANGED hostnames (count)', 'yellow', counts.changed, iterChanged(db, baseline.id, incoming.id), limit, (r) => {
      const delta = (r.newCount ?? 0) - (r.oldCount ?? 0);
      const sign = delta > 0 ? '+' : '';
      return `${r.hostname.padEnd(36)} ${c('gray', `${r.oldCount} -> ${r.newCount} (${sign}${delta})`)}`;
    });
  }
  if (counts.added === 0 && counts.removed === 0 && counts.changed === 0) {
    console.log(c('green', 'No differences - incoming data matches the baseline exactly.'));
  }
}
