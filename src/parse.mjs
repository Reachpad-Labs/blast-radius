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
// RULES  (measured on a real server-filesystem run: 30,678 lines -> 2 events)
//   1. Keep only lines containing "return=". Each syscall also emits an entry
//      line and a "close time.busy=" line; keep those and every count triples.
//   2. Keep only calls that are actual access or egress:
//        path_open2 path_open sock_open sock_connect sock_send
//        resolve proc_exec proc_spawn path_unlink_file
//      Everything else is bookkeeping. path_filestat_get alone was 19,722 of
//      the 30,678 lines: that is Node resolving modules, not touching secrets.
//   3. Drop paths under /nix/store, /app, /bin, /lib. That is the runtime and
//      the specimen reading their own code. Note /app, not /app/node_modules:
//      a server loads its own index.js and package.json too.
//   4. Drop Errno::noent. A file that does not exist was not accessed. This is
//      what removes Node startup probes for openssl.cnf, config.gypi and
//      doc/api/cli.md, and it is the single highest-yield rule.
//   5. decision = "deny" when the errno is perm or acces, and ALSO when a
//      sock_connect returns io. Measured: a DNS denial gives Errno::perm, but
//      a raw-IP connect under default-deny networking gives Errno::io.
//   6. canary_hit = any CANARY- substring appearing in the args.
//
// After all six, a real run of @modelcontextprotocol/server-filesystem asked to
// read the seeded key leaves exactly two events: /dev/null, and
//   path_open2 path="/home/.ssh/id_ed25519" ret_fd=13
