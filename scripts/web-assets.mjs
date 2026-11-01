// build step: copy the web UI assets into dist/ (tsc only compiles .ts)
import { copyFileSync, cpSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

mkdirSync('dist/web', { recursive: true });
cpSync('src/web', 'dist/web', { recursive: true, filter: (f) => !f.endsWith('.ts') });

// chart.umd.min.js is not in chart.js exports map; resolve the package dir and copy by path
const chartDist = dirname(createRequire(import.meta.url).resolve('chart.js'));
copyFileSync(join(chartDist, 'chart.umd.min.js'), 'dist/web/chart.umd.js');
