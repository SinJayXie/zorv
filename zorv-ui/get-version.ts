import * as path from 'path';
import * as fs from 'fs';

// Resolve the repo root Cargo.toml. `pnpm build`/`pnpm dev` run from zorv-ui/,
// so the repo root is one level up.
const CARGO_TOML = path.join(process.cwd(), '../Cargo.toml');

// Parse the `version = "x.y.z"` line inside the [package] section.
const VERSION_RE = /^version\s*=\s*"([^"]+)"/m;

export function getBuildVersion(): string {
  const raw = fs.readFileSync(CARGO_TOML, 'utf-8');
  const match = raw.match(VERSION_RE);
  if (!match) {
    throw new Error(`version not found in ${CARGO_TOML}`);
  }
  return match[1];
}
