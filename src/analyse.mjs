// STAGE 5 — turn events into claims. Pure function, no Wasmer, fully testable
// against evidence/syscalls-sample.log.
//
// analyse(events, { sinkHits, canaries }) -> Findings
//
// Findings = {
//   reads_credentials:  [{ path, canary }]        which canary files were opened
//   egress:             [{ host, port, blocked }] from resolve / sock_connect
//   bytes_out:          number                    sum of sock_send bytes_written
//   canary_in_payload:  [canary]                  FROM sinkHits ONLY
//   writes_outside_cwd: [path]
//   fingerprinting:     [string]                  reads of process.versions etc.
// }
//
// THE CLAIM TIERS — keep these apart, a judge will ask which one a line is.
//   observed-from-trace: reads_credentials, egress, bytes_out. Available for
//                        any specimen dialing anywhere.
//   proven-at-sink:      canary_in_payload. Requires egress routed to our sink.
//
// Never derive canary_in_payload from the trace. Payload bytes are NOT in the
// trace; sock_send reports bytes_written only.

export function analyse(events, { sinkHits = [], canaries }) {
  throw new Error('not implemented: see the Findings shape above');
}
