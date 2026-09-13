// STAGE 6 — render the verdict card.
//
// renderCard(findings, { name, version, integrity }) -> html string
//
// One page per specimen: pinned name and version, capabilities observed,
// canaries touched, canaries proven to have left, hosts dialed, verdict line.
//
// Must render from a saved JSON file with no live run, so the video can never
// be broken by a flaky detonation.
//
// Describe capabilities, never accuse. "transmits tool arguments to host X",
// not "malware". We are naming real packages.

export function renderCard(findings, meta) {
  throw new Error('not implemented');
}
