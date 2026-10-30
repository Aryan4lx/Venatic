import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';

export function resolveDbPath(override?: string): string {
  const p = override ?? process.env.THREATHUNT_DB ?? join(homedir(), '.threathunt', 'threathunt.db');
  mkdirSync(dirname(p), { recursive: true });
  return p;
}
