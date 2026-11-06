// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const js = readFileSync('pkg/bitbox_api_bg.js', 'utf8');
const types = readFileSync('pkg/bitbox_api.d.ts', 'utf8');
const methods = ['setPassword', 'setDeviceName', 'insertSdcard', 'createBackup', 'performAttestation', 'close', 'intoBitBox', 'intoBootloader', 'isBootloader', 'flashSignedFirmware', 'btcSignPSBT', 'btcRegisterScriptConfig', 'btcIsScriptConfigRegistered', 'btcAddress'];
for (const method of methods) {
  assert(js.includes(`${method}(`), `Missing JS binding: ${method}`);
  assert(types.includes(`${method}(`), `Missing declaration: ${method}`);
}
assert(js.includes('bitbox02ConnectAnyWebHID'), 'Missing WebHID connection');
const module = await WebAssembly.compile(readFileSync('pkg/bitbox_api_bg.wasm'));
const exports = new Set(WebAssembly.Module.exports(module).map(({ name }) => name));
for (const name of ['bitbox_close', 'bitbox_performAttestation', 'bitbox02ConnectAnyWebHID', 'pairedbitbox_createBackup', 'pairedbitbox_setPassword', 'bootloader_flashSignedFirmware']) {
  assert(exports.has(name), `Missing WASM export: ${name}`);
}
console.log('Verified setup, attestation, bootloader, policy and signing bindings.');
