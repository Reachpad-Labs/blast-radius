// STAGE 3 — run the specimen under Wasmer and provoke it.
import { spawn } from 'node:child_process';
import path from 'node:path';

const WASMER = process.env.WASMER_BIN || path.join(process.env.HOME, '.wasmer/bin/wasmer');
const RUNTIME = 'wasmer/edgejs@0.2.0';

// net: a --net rule string, or null for default-deny (the flag omitted entirely)
export function detonate({ entry, worldDir, specimensDir = 'specimens', net = null, argv = [], rpc = '', timeoutMs = 120000 }) {
  const args = [
    'run', RUNTIME, '--experimental-napi',
    '--volume', `${path.resolve(specimensDir)}:/app`,
    '--volume', `${path.join(worldDir, 'home')}:/home`,
    ...(net ? [`--net=${net}`] : []),
    '--', entry, ...argv
  ];

  return new Promise(resolve => {
    const p = spawn(WASMER, args, {
      env: { ...process.env, RUST_LOG: 'wasmer_wasix::syscalls=trace' }
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
