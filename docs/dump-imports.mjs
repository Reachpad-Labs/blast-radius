import { readFileSync } from 'node:fs';
const buf = readFileSync('pyunpack/modules/python');
const mod = await WebAssembly.compile(buf);
const imps = WebAssembly.Module.imports(mod);
const byMod = {};
for (const i of imps) (byMod[i.module] ??= []).push(i.name);
for (const [m, names] of Object.entries(byMod)) {
  console.log(`\n== ${m}  (${names.length} imports) ==`);
  console.log(names.sort().join('  '));
}
console.log('\n== exports (first 25) ==');
console.log(WebAssembly.Module.exports(mod).map(e=>e.name).slice(0,25).join('  '));
