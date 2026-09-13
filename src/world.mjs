// STAGE 2 — build the canary world.
//
// seedWorld(destDir)
//   -> { dir, home, probePath, canaries, env }
//
// Copies fixtures/world into destDir and replaces every CANARY-xxxxx
// placeholder with a freshly generated unique string, one per file. A fresh
// canary per run is what makes a later match proof rather than a heuristic.
//
// Two surfaces carry canaries, because a real box has two:
//   files — mounted at /home and /app in the guest
//   env   — handed to the guest with --env, because Wasmer inherits NOTHING
//
// Env canaries can only ever be proven at the sink: environ_get copies the
// whole block in one call, so the trace shows that the environment was read
// and never which variable was taken.
//
// The SAME world must be used for every specimen in one sweep, or the
// results are not comparable.
import { cp, readFile, writeFile, rm, mkdir, readdir } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';

const mint = () => 'CANARY-' + randomBytes(4).toString('hex');
const PLACEHOLDER = /CANARY-[A-Za-z0-9]+/g;

// The guest's home. Real boxes put it under a named user, and specimens that
// resolve ~ or read $HOME must land on the seeded tree, not on /.
export const GUEST_USER = 'dev';
export const GUEST_HOME = `/home/${GUEST_USER}`;

// A shell environment with the shape of a working dev box. The secrets carry
// canaries; the rest is there so a specimen that dumps env sees a plausible
// machine rather than an obvious trap.
function seedEnv() {
  const env = {
    HOME: GUEST_HOME,
    USER: GUEST_USER,
    LOGNAME: GUEST_USER,
    SHELL: '/bin/bash',
    PATH: `${GUEST_HOME}/.local/bin:${GUEST_HOME}/.cargo/bin:/usr/local/bin:/usr/bin:/bin`,
    PWD: `${GUEST_HOME}/projects/acme-api`,
    LANG: 'en_US.UTF-8',
    TERM: 'xterm-256color',
    TZ: 'America/Los_Angeles',
    NODE_ENV: 'production',
    EDITOR: 'vim',
    GITHUB_TOKEN: `ghp_vC1sJ8hY3Lq2ZmX0tR7wX4bN6${mint()}`,
    AWS_ACCESS_KEY_ID: `AKIA3XQ7NLPZ4RW${mint()}`,
    AWS_SECRET_ACCESS_KEY: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYz${mint()}`,
    OPENAI_API_KEY: `sk-proj-Lq2ZmX0tR7wX4bN6vC1sJ8hY3${mint()}`,
    ANTHROPIC_API_KEY: `sk-ant-api03-X4bN6vC1sJ8hY3Lq2ZmX0tR7w${mint()}`,
    STRIPE_SECRET_KEY: `sk_live_51MqR7wX4bN6vC1sJ8hY3Lq2Z${mint()}`,
    DATABASE_URL: `postgresql://app:${mint()}@db.acme.internal:5432/prod`,
    SLACK_BOT_TOKEN: `xoxb-481920374615-8hY3Lq2ZmX0tR7wX4bN6vC1sJ${mint()}`
  };
  return env;
}

async function* walk(dir) {
  for (const ent of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) yield* walk(full);
    else if (ent.isFile()) yield full;
  }
}

export async function seedWorld(destDir, { template = 'fixtures/world' } = {}) {
  await rm(destDir, { recursive: true, force: true });
  await mkdir(path.dirname(destDir), { recursive: true });
  await cp(template, destDir, { recursive: true });

  // Every fixture carrying a placeholder gets its own fresh canary, keyed by
  // the path it lives at, so a hit names the file it came from. Adding a
  // fixture needs no change here.
  const canaries = {};
  for await (const file of walk(destDir)) {
    let text;
    try { text = await readFile(file, 'utf8'); } catch { continue; }
    if (!PLACEHOLDER.test(text)) continue;
    PLACEHOLDER.lastIndex = 0;
    const fresh = mint();
    await writeFile(file, text.replace(PLACEHOLDER, fresh));
    canaries[path.relative(destDir, file).split(path.sep).join('/')] = fresh;
  }

  const env = seedEnv();
  for (const [k, v] of Object.entries(env)) {
    const m = PLACEHOLDER.exec(v);
    PLACEHOLDER.lastIndex = 0;
    if (m) canaries[`env:${k}`] = m[0];
  }

  return {
    dir: path.resolve(destDir),
    home: GUEST_HOME,
    probePath: `${GUEST_HOME}/.ssh/id_ed25519`,
    canaries,
    env
  };
}
