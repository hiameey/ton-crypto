"use strict";
/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveEd25519PathSync = exports.deriveEd25519Path = exports.deriveED25519HardenedKeySync = exports.deriveED25519HardenedKey = exports.getED25519MasterKeyFromSeedSync = exports.getED25519MasterKeyFromSeed = void 0;
const hmac_sha512_1 = require("../primitives/hmac_sha512");
const ED25519_CURVE = 'ed25519 seed';
const HARDENED_OFFSET = 0x80000000;
async function getED25519MasterKeyFromSeed(seed) {
    return getED25519MasterKeyFromSeedSync(seed);
}
exports.getED25519MasterKeyFromSeed = getED25519MasterKeyFromSeed;
function getED25519MasterKeyFromSeedSync(seed) {
    const I = (0, hmac_sha512_1.hmac_sha512_sync)(ED25519_CURVE, seed);
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    return {
        key: IL,
        chainCode: IR,
    };
}
exports.getED25519MasterKeyFromSeedSync = getED25519MasterKeyFromSeedSync;
async function deriveED25519HardenedKey(parent, index) {
    return deriveED25519HardenedKeySync(parent, index);
}
exports.deriveED25519HardenedKey = deriveED25519HardenedKey;
function deriveED25519HardenedKeySync(parent, index) {
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
exports.deriveED25519HardenedKeySync = deriveED25519HardenedKeySync;
async function deriveEd25519Path(seed, path) {
    return deriveEd25519PathSync(seed, path);
}
exports.deriveEd25519Path = deriveEd25519Path;
function deriveEd25519PathSync(seed, path) {
    let state = getED25519MasterKeyFromSeedSync(seed);
    let remaining = [...path];
    while (remaining.length > 0) {
        let index = remaining[0];
        remaining = remaining.slice(1);
        state = deriveED25519HardenedKeySync(state, index);
    }
    return state.key;
}
exports.deriveEd25519PathSync = deriveEd25519PathSync;
