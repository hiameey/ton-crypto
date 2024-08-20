"use strict";
/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveMnemonicsPathSync = exports.deriveMnemonicsPath = exports.deriveMnemonicHardenedKeySync = exports.deriveMnemonicHardenedKey = exports.getMnemonicsMasterKeyFromSeedSync = exports.getMnemonicsMasterKeyFromSeed = void 0;
const mnemonic_1 = require("../mnemonic/mnemonic");
const hmac_sha512_1 = require("../primitives/hmac_sha512");
const HARDENED_OFFSET = 0x80000000;
const MNEMONICS_SEED = 'TON Mnemonics HD seed';
async function getMnemonicsMasterKeyFromSeed(seed) {
    return getMnemonicsMasterKeyFromSeedSync(seed);
}
exports.getMnemonicsMasterKeyFromSeed = getMnemonicsMasterKeyFromSeed;
function getMnemonicsMasterKeyFromSeedSync(seed) {
    const I = (0, hmac_sha512_1.hmac_sha512_sync)(MNEMONICS_SEED, seed);
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
        key: IL,
        chainCode: IR,
    };
}
exports.getMnemonicsMasterKeyFromSeedSync = getMnemonicsMasterKeyFromSeedSync;
async function deriveMnemonicHardenedKey(parent, index) {
    return deriveMnemonicHardenedKeySync(parent, index);
}
exports.deriveMnemonicHardenedKey = deriveMnemonicHardenedKey;
function deriveMnemonicHardenedKeySync(parent, index) {
    if (index >= HARDENED_OFFSET) {
        throw Error('Key index must be less than offset');
    }
    // Key Derive Path: 0x00 + parent.key + index;
    const indexBuffer = Buffer.alloc(4);
    indexBuffer.writeUInt32BE(index + HARDENED_OFFSET, 0);
    const data = Buffer.concat([Buffer.alloc(1, 0), parent.key, indexBuffer]);
    // Derive key
    const I = (0, hmac_sha512_1.hmac_sha512_sync)(parent.chainCode, data);
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
        key: IL,
        chainCode: IR,
    };
}
exports.deriveMnemonicHardenedKeySync = deriveMnemonicHardenedKeySync;
async function deriveMnemonicsPath(seed, path, wordsCount = 24, password) {
    return deriveMnemonicsPathSync(seed, path, wordsCount, password);
}
exports.deriveMnemonicsPath = deriveMnemonicsPath;
function deriveMnemonicsPathSync(seed, path, wordsCount = 24, password) {
    let state = getMnemonicsMasterKeyFromSeedSync(seed);
    let remaining = [...path];
    while (remaining.length > 0) {
        let index = remaining[0];
        remaining = remaining.slice(1);
        state = deriveMnemonicHardenedKeySync(state, index);
    }
    return (0, mnemonic_1.mnemonicFromRandomSeed)(state.key, wordsCount, password);
}
exports.deriveMnemonicsPathSync = deriveMnemonicsPathSync;
