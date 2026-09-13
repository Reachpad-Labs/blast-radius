// The frozen event schema. Every stage speaks this. Do not renegotiate it.
//
//   { ts, call, args, canary_hit, decision }
//
// ts         seconds since the run started, float
// call       WASI/WASIX function name, e.g. "path_open2", "sock_connect", "resolve"
// args       object of the arguments the trace exposed, e.g. { path } or { host, port }
// canary_hit the CANARY-xxxxx string found in args, or null
// decision   "allow" | "deny"   (deny when the runtime returned Errno::perm / Errno::acces)

export const DECISION = { ALLOW: 'allow', DENY: 'deny' };

export function event(ts, call, args, canary_hit = null, decision = DECISION.ALLOW) {
  return { ts, call, args, canary_hit, decision };
}
