// STAGE 3 — run the specimen under Wasmer and provoke it.
import { spawn } from 'node:child_process';
import { cp, rm } from 'node:fs/promises';
import path from 'node:path';
import { GUEST_HOME } from './world.mjs';

const WASMER = process.env.WASMER_BIN || path.join(process.env.HOME, '.wasmer/bin/wasmer');
// Two Edge.js packages on the registry, same Node 24 userland, different engine:
//   host     wasmer/edgejs          V8 provided by the wasmer binary over N-API.
//            Fast (0.4s boots). Wasmer's own SECURITY-HOST-JS-NAPI.md says this
//            mode is not yet a security boundary; only syscalls are confined.
//   quickjs  wasmer/edgejs-quickjs  QuickJS compiled into the wasm module, so the
//            engine is inside the sandbox too. ~3x slower boots, same trace.
// Both need no dlopen: "dlfcn unsupported on WASIX", so no .node addon loads in either.
export const ENGINES = {
  host:    { runtime: 'wasmer/edgejs@0.2.0',         flags: ['--experimental-napi'] },
  quickjs: { runtime: 'wasmer/edgejs-quickjs@0.2.0', flags: [] }
};
export const DEFAULT_ENGINE = process.env.BLAST_ENGINE || 'host';

// Volumes are read-write and Wasmer has no read-only mount, so a specimen CAN
// write to whatever we hand it — measured: it planted a file in specimens/.
// Detonate a copy, never the tree we keep. The world is already a per-run copy
// for the same reason.
export async function stageSpecimens(src = 'specimens', dest = '.run/specimens') {
  await rm(dest, { recursive: true, force: true });
  await cp(src, dest, { recursive: true });
  return path.resolve(dest);
}

// net: a --net rule string, or null for default-deny (the flag omitted entirely)
// env: the guest environment, passed as --env KEY=VALUE. Wasmer inherits NOTHING
//      from the host, so an unseeded run hands the specimen process.env === {} —
//      and env is where the credentials on a real box actually live. HOME is
//      always set: without it Node throws uv_os_homedir ENOENT before a server
//      even loads (measured on @playwright/mcp), and it has to point at the
//      seeded user's directory or ~/.ssh resolves nowhere.
// mounts: [{ host, guest }] from seedWorld — /home, /etc, /proc, /sys. Mounting
//         over the image's /etc is safe: DNS still resolves, measured.
// trace: false skips RUST_LOG so a boot test does not pay for 30k trace lines
export function detonate({ entry, worldDir, mounts = null, specimensDir = 'specimens', net = null, argv = [], env = {}, rpc = '', timeoutMs = 120000, trace = true, engine = DEFAULT_ENGINE }) {
  const eng = ENGINES[engine];
  if (!eng) throw new Error(`unknown engine ${engine}; use one of ${Object.keys(ENGINES).join(', ')}`);
  const world = mounts || [{ host: path.join(worldDir, 'home'), guest: '/home' }];
  const args = [
    'run', eng.runtime, ...eng.flags,
    '--volume', `${path.resolve(specimensDir)}:/app`,
    ...world.flatMap(m => ['--volume', `${m.host}:${m.guest}`]),
    ...(net ? [`--net=${net}`] : []),
    ...Object.entries({ HOME: GUEST_HOME, ...env }).flatMap(([k, v]) => ['--env', `${k}=${v}`]),
    '--', entry, ...argv
  ];

  return new Promise(resolve => {
    const p = spawn(WASMER, args, {
      env: { ...process.env, RUST_LOG: trace ? 'wasmer_wasix::syscalls=trace' : 'off' }
    });
    let stdout = '', stderr = '';
    p.stdout.on('data', d => { stdout += d; });
    p.stderr.on('data', d => { stderr += d; });
    const kill = setTimeout(() => p.kill('SIGKILL'), timeoutMs);
    p.on('close', code => { clearTimeout(kill); resolve({ stdout, stderr, exitCode: code, argv: args }); });
    p.stdin.write(rpc);
    p.stdin.end();
  });
}

export const rpcLines = (...objs) => objs.map(o => JSON.stringify(o)).join('\n') + '\n';

export const INIT = {
  jsonrpc: '2.0', id: 1, method: 'initialize',
  params: { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'blast-radius', version: '0.1' } }
};
export const LIST = { jsonrpc: '2.0', id: 2, method: 'tools/list' };

// Build a plausible argument object from a tool's inputSchema. We only ever see
// what we provoke, so every tool gets called.
export function argsFor(schema, world) {
  const out = {};
  const props = schema?.properties || {};
  for (const [k, spec] of Object.entries(props)) {
    if (!(schema.required || []).includes(k)) continue;
    if (/path|file|dir/i.test(k)) out[k] = world.probePath;
    else if (spec.type === 'number' || spec.type === 'integer') out[k] = 1;
    else if (spec.type === 'boolean') out[k] = true;
    else if (spec.type === 'array') out[k] = [];
    else if (spec.type === 'object') out[k] = {};
    else out[k] = 'blast radius probe';
  }
  return out;
}
