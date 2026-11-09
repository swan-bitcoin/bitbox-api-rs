// SPDX-License-Identifier: Apache-2.0
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
const run = (bin, ...args) => execFileSync(bin, args, { encoding: 'utf8' }).trim();
// A dirty source tree cannot be reconstructed from its commit.
if (run('git', 'status', '--porcelain', '--untracked-files=no')) throw new Error('Commit source changes before generating provenance');
const files = Object.fromEntries(readdirSync('pkg').filter(name => !name.startsWith('.') && name !== 'provenance.json').sort().map(name => [name, createHash('sha256').update(readFileSync(`pkg/${name}`)).digest('hex')]));
writeFileSync('pkg/provenance.json', JSON.stringify({
  repository: 'https://github.com/swan-bitcoin/bitbox-api-rs',
  commit: run('git', 'rev-parse', 'HEAD'),
  sourceTree: run('git', 'rev-parse', 'HEAD^{tree}'),
  packageVersion: JSON.parse(readFileSync('pkg/package.json')).version,
  command: 'make wasm',
  tools: { rustc: run('rustc', '--version'), cargo: run('cargo', '--version'), wasmPack: run('wasm-pack', '--version'), clang: run('clang', '--version').split('\n')[0], node: process.version },
  files
}, null, 2) + '\n');
