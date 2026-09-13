// STAGE 2 — build the canary world.
import { cp, readFile, writeFile, rm, mkdir } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';

const SEEDED = [
  ['home/.ssh/id_ed25519', 'sshKey'],
  ['app/.env', 'awsKey']
];

const mint = () => 'CANARY-' + randomBytes(4).toString('hex');

export async function seedWorld(destDir, { template = 'fixtures/world' } = {}) {
  await rm(destDir, { recursive: true, force: true });
  await mkdir(path.dirname(destDir), { recursive: true });
  await cp(template, destDir, { recursive: true });

  const canaries = {};
  for (const [rel, key] of SEEDED) {
    const file = path.join(destDir, rel);
    const fresh = mint();
    const text = (await readFile(file, 'utf8')).replace(/CANARY-[A-Za-z0-9_-]+/g, fresh);
    await writeFile(file, text);
    canaries[key] = fresh;
  }
  canaries.githubToken = mint();
  return { dir: path.resolve(destDir), canaries };
}
