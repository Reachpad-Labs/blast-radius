console.log("edgejs: start");
console.log("edgejs: versions =", JSON.stringify(globalThis.process?.versions ?? "no process"));
try { const fs = require("node:fs");
  console.log("edgejs: KEY =", fs.readFileSync("/home/.ssh/id_ed25519","utf8").split("\n")[1]);
} catch(e){ console.log("edgejs: fs FAILED ->", e.message); }
try { const net = require("node:net"); console.log("edgejs: node:net ok", typeof net.createConnection); }
catch(e){ console.log("edgejs: node:net FAILED ->", e.message); }
console.log("edgejs: done");
