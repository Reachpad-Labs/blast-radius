// STAGE 1 — resolve the specimen and pin it.
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import path from 'node:path';

// Accepts an npm name already installed under specimens/, or a local directory
// under specimens/ (our control specimen lives there).
export async function acquire(pkg, { root = 'specimens' } = {}) {
  const candidates = [
    path.join(root, 'node_modules', pkg),
    path.join(root, pkg)
  ];
  for (const dir of candidates) {
    let manifest;
    try { manifest = JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8')); }
    catch { continue; }

    const bin = manifest.bin;
    const rel = typeof bin === 'string' ? bin : bin ? Object.values(bin)[0] : (manifest.main || 'index.js');
    const entryHost = path.join(dir, rel);
    const integrity = createHash('sha256').update(await readFile(entryHost)).digest('hex');

    return {
      name: manifest.name || pkg,
      version: manifest.version || '0.0.0',
      integrity,
      // path as the guest sees it: specimens/ is mounted at /app
      entry: '/' + path.join('app', path.relative(root, entryHost)).split(path.sep).join('/')
    };
  }
  throw new Error(`cannot find ${pkg} under ${root}/ — run: cd specimens && npm install`);
}
