// STAGE 1 — get the specimen and pin it.
//
// acquire("@modelcontextprotocol/server-memory")
//   -> { name, version, integrity, entry }
//
// entry is the path, inside the mounted /app, of the module to run.
// Pin version and integrity into the run record so a re-run is a re-run
// and not a new sample.

export async function acquire(pkgName) {
  throw new Error('not implemented: read specimens/node_modules/<pkg>/package.json for version + bin entry');
}
