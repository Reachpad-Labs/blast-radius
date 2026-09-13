// The sweep: which packages we detonate, and what each one needs to boot.
//
// Every key and token below is fake. Egress is denied by default, so nothing
// here can reach a real service, and a server that ships them somewhere is
// exactly the behaviour we are here to observe. The seeded GITHUB_TOKEN canary
// is injected by the runner on top of these.
//
// argv  extra command-line arguments after the entry module
// env   guest environment variables, passed with --env
// control  true for our own deliberately malicious specimen; excluded from the
//          coverage count because it is not a package anyone installs
export const SPECIMENS = [
  { pkg: '@modelcontextprotocol/server-memory', note: 'official' },
  { pkg: '@modelcontextprotocol/server-filesystem', argv: ['/home'], note: 'official; allowed roots are argv' },
  { pkg: '@modelcontextprotocol/server-everything', note: 'official reference server' },
  { pkg: '@modelcontextprotocol/server-sequential-thinking', note: 'official' },
  { pkg: '@modelcontextprotocol/server-github', note: 'official, archived upstream; token from env' },
  { pkg: '@modelcontextprotocol/server-postgres', argv: ['postgresql://127.0.0.1:5432/blast'], note: 'official, archived upstream; DB url is argv' },
  { pkg: '@upstash/context7-mcp', note: 'third-party, Upstash' },
  { pkg: '@playwright/mcp', note: 'third-party, Microsoft' },
  { pkg: '@notionhq/notion-mcp-server', env: { NOTION_TOKEN: 'ntn_blastradius_fake_token' }, note: 'third-party, Notion' },
  { pkg: '@stripe/mcp', argv: ['--api-key=sk_test_blastradius_fake'], note: 'third-party, Stripe; a stdio proxy to mcp.stripe.com' },
  // added on demand through run.mjs after the first sweep
  { pkg: 'tavily-mcp', env: { TAVILY_API_KEY: 'tvly-blastradius-fake' }, note: 'third-party, Tavily' },
  { pkg: '@hubspot/mcp-server', env: { PRIVATE_APP_ACCESS_TOKEN: 'pat-blastradius-fake' }, note: 'third-party, HubSpot' },
  { pkg: 'exa-mcp-server', env: { EXA_API_KEY: 'blastradius-fake' }, note: 'third-party, Exa' },
  { pkg: '@sentry/mcp-server', env: { SENTRY_ACCESS_TOKEN: 'blastradius-fake' }, timeoutMs: 60000, note: 'third-party, Sentry' },
  { pkg: 'firecrawl-mcp', env: { FIRECRAWL_API_KEY: 'fc-blastradius-fake' }, note: 'third-party, Firecrawl' },
  { pkg: 'mcp-server-kubernetes', note: 'third-party; shells out to kubectl, which is not in the sandbox' },
  { pkg: 'evil-notes', control: true, note: 'control specimen, lives in specimens/evil-notes' }
];

// What every specimen gets on top of the seeded world, so a leaked token is a
// canary and not a real key. The world already mints GITHUB_TOKEN; this is the
// alias the official GitHub server reads, pointed at the same value so a hit at
// the sink is attributable to one canary rather than two.
// Takes the world from seedWorld(). Tolerates a bare canary map too, because
// the boot test used to pass one and a crash in a helper is a poor way to find
// out — measured: it took down a whole regeneration run.
export function seededEnv(world = {}) {
  const token = world.env?.GITHUB_TOKEN            // the world, as seedWorld returns it
    ?? world.githubToken                            // the old canary map
    ?? world['env:GITHUB_TOKEN'];                   // a canary map keyed by origin
  return token ? { GITHUB_TOKEN: token, GITHUB_PERSONAL_ACCESS_TOKEN: token } : {};
}

export function specimenFor(pkg) {
  return SPECIMENS.find(s => s.pkg === pkg) || { pkg };
}
