// STAGE 2 — build the canary world.
//
// seedWorld(destDir)
//   -> { dir, canaries: { sshKey, awsKey, githubToken } }
//
// Copies fixtures/world into destDir and replaces every CANARY-xxxxx
// placeholder with a freshly generated unique string. A fresh canary per run
// is what makes a later match proof rather than a heuristic.
//
// The SAME world must be used for every specimen in one sweep, or the
// results are not comparable.

export async function seedWorld(destDir) {
  throw new Error('not implemented: copy fixtures/world, substitute fresh CANARY- strings, return the map');
}
