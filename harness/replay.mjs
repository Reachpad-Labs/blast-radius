#!/usr/bin/env node
// Re-run the analyser over saved evidence and diff the verdicts.
//
//   node harness/replay.mjs
//
// analyse.mjs is pure, so every card already carries everything it needs: the
// events, and the policy that judged them. After any change to the analyser this
// says which verdicts moved and why, in seconds, without booting Wasmer once.
//
// It only replays what the trace can show. The two channels measured outside the
// trace — what the server said back, and what it copied on disk — are not in a
// saved card, so a card whose verdict came from those replays as something
// milder. Those are marked "not replayable" rather than counted as a difference.
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { analyse } from '../src/analyse.mjs';

const dir = process.argv[2] || 'evidence/cards';
const files = (await readdir(dir)).filter(f => f.endsWith('.json')).sort();

let moved = 0, same = 0, skipped = 0;
for (const f of files) {
  const card = JSON.parse(await readFile(path.join(dir, f), 'utf8'));
  if (!card.events || !card.findings) { skipped++; continue; }

  const before = card.findings.verdict;
  const outsideTrace = (card.findings.returned_to_model?.length || 0) + (card.findings.staged_on_disk?.length || 0);
  const after = analyse(card.events, {
    sinkHits: card.findings.canary_in_payload || [],
    canaries: Object.fromEntries((card.findings.canary_in_payload || []).map(c => [c, c])),
    policy: card.findings.policy || {}
  }).verdict;

  const name = f.replace(/\.json$/, '');
  if (before.level === after.level && before.line === after.line) { same++; continue; }
  if (outsideTrace) {
    console.log(`~ ${name.padEnd(46)} ${before.level} -> ${after.level}   (not replayable: ${outsideTrace} found outside the trace)`);
    skipped++;
    continue;
  }
  moved++;
  console.log(`! ${name}`);
  console.log(`    was: ${before.level.padEnd(10)} ${before.line}`);
  console.log(`    now: ${after.level.padEnd(10)} ${after.line}`);
}

console.log(`\n${same} unchanged, ${moved} moved, ${skipped} skipped of ${files.length} cards`);
process.exit(moved ? 1 : 0);
