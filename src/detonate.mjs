// STAGE 3 — run the specimen and provoke it.
//
// detonate({ entry, worldDir, net, rpc })
//   -> { stdout, stderr, exitCode }
//
// net: a --net rule string. "dns:deny=*:*" for scan mode, undefined to allow.
// rpc: JSON-RPC lines to feed on stdin (initialize, tools/list, tools/call...).
//
// The exact invocation, verified working:
//
//   RUST_LOG="wasmer_wasix::syscalls=trace" \
//   wasmer run wasmer/edgejs@0.2.0 --experimental-napi \
//     --volume "<worldDir>/app:/app" --volume "<worldDir>/home:/home" \
//     --net="<net>" -- <entry> [args] < rpc.txt 2>trace.log
//
// You only ever see what you provoke: a server whose tools are never called
// does nothing incriminating. Call every tool tools/list returns.
//
// GOTCHA server-filesystem takes its allowed directories as argv. Pass /home
// or it refuses every path with an error that looks like our sandbox.

export async function detonate({ entry, worldDir, net, rpc }) {
  throw new Error('not implemented: spawn wasmer with the flags above, capture stdout and stderr');
}
