// STAGE 1 — resolve the specimen and pin it.
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import path from 'node:path';

// Accepts an npm name (installed on demand), or a local directory under
// specimens/ (our control specimen lives there).
export async function acquire(pkg, { root = 'specimens', install = true } = {}) {
  const name = pkg.replace(/(.)@[^/]+$/, '$1');   // strip a trailing @version
  const found = await locate(name, root);
  if (found) return found;
  if (install && /^(@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*$/i.test(name)) {
    // --ignore-scripts is not optional. A postinstall runs on the HOST, outside
    // the sandbox, so a package that wants your keys could take them there
    // before we ever detonate it. The sandbox is the only place it gets to run.
    process.stderr.write(`[0/3] ${pkg} is not under ${root}/, installing with scripts disabled\n`);
    const r = spawnSync('npm', ['install', '--save', '--ignore-scripts', '--no-audit', '--no-fund', pkg], { cwd: root, stdio: ['ignore', 'ignore', 'pipe'] });
    if (r.status !== 0) throw new Error(`npm install ${pkg} failed: ${String(r.stderr).trim().split('\n').slice(-3).join(' | ')}`);
    const again = await locate(name, root);
    if (again) return again;
  }
  throw new Error(`cannot find ${pkg} under ${root}/`);
}

async function locate(pkg, root) {
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
  return null;
}
