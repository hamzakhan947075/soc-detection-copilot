'use strict';

// Runs ESLint from the repo root (eslint.config.js there covers both
// backend/src+tests and frontend/js) via the Node API, since the CLI's
// "base path" restriction otherwise rejects globs outside npm's own cwd
// (backend/) when this is invoked as `npm run lint` from that directory.
const path = require('path');
const { ESLint } = require('eslint');

async function main() {
  const repoRoot = path.join(__dirname, '..', '..');
  const eslint = new ESLint({ cwd: repoRoot });
  const results = await eslint.lintFiles(['backend/src/**/*.js', 'backend/tests/**/*.js', 'frontend/js/**/*.js']);

  const formatter = await eslint.loadFormatter('stylish');
  const output = formatter.format(results);
  if (output) {
    console.log(output);
  }

  const hasErrors = results.some((result) => result.errorCount > 0);
  process.exitCode = hasErrors ? 1 : 0;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
