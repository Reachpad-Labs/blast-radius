// STAGE 4 — turn Wasmer's trace into schema events.
//
// parseTrace(stderrText, { canaries }) -> Event[]
//
// Input lines look like:
//   ...TRACE ThreadId(22) path_open2: wasmer_wasix::syscalls::wasix::path_open2:
//        return=Ok(Errno::success) dirfd=5 path="/home/.ssh/id_ed25519" ret_fd=6
//   ...TRACE ThreadId(22) resolve: wasmer_wasix::syscalls::wasix::resolve:
//        return=Ok(Errno::perm) port=0 host="example.com"
//
// RULES
//   1. Keep only lines containing "return=". Each syscall also emits an entry
//      line and a "close time.busy=" line; keep those and every count triples.
//   2. Drop anything whose path starts with /nix/store, /bin or /lib. That is
//      the runtime reading its own stdlib and it is ~95% of the volume.
//      A trivial run is ~3900 lines; a parsed run should be under 40.
//   3. decision = "deny" when the errno is perm or acces, else "allow".
//   4. canary_hit = any CANARY- substring appearing in the args.

export function parseTrace(stderrText, { canaries }) {
  throw new Error('not implemented: see RULES above');
}
