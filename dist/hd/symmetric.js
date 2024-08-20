"use strict";
/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.deriveSymmetricPathSync = exports.deriveSymmetricPath = exports.deriveSymmetricHardenedKeySync = exports.deriveSymmetricHardenedKey = exports.getSymmetricMasterKeyFromSeedSync = exports.getSymmetricMasterKeyFromSeed = void 0;
const hmac_sha512_1 = require("../primitives/hmac_sha512");
const SYMMETRIC_SEED = 'Symmetric key seed';
async function getSymmetricMasterKeyFromSeed(seed) {
    return getSymmetricMasterKeyFromSeedSync(seed);
}
exports.getSymmetricMasterKeyFromSeed = getSymmetricMasterKeyFromSeed;
function getSymmetricMasterKeyFromSeedSync(seed) {
    const I = (0, hmac_sha512_1.hmac_sha512_sync)(SYMMETRIC_SEED, seed);
    const IL = I.slice(32);
    const IR = I.slice(0, 32);
    return {
        key: IL,
        chainCode: IR,
    };
}
exports.getSymmetricMasterKeyFromSeedSync = getSymmetricMasterKeyFromSeedSync;
async function deriveSymmetricHardenedKey(parent, offset) {
    return deriveSymmetricHardenedKeySync(parent, offset);
}
exports.deriveSymmetricHardenedKey = deriveSymmetricHardenedKey;
function deriveSymmetricHardenedKeySync(parent, offset) {
    // Prepare data
    const data = Buffer.concat([Buffer.alloc(1, 0), Buffer.from(offset)]);
    // Derive key
    const I = (0, hmac_sha512_1.hmac_sha512_sync)(parent.chainCode, data);
    const IL = I.slice(32);
    const IR = I.slice(0, 32);
    return {
        key: IL,
        chainCode: IR,
    };
}
exports.deriveSymmetricHardenedKeySync = deriveSymmetricHardenedKeySync;
async function deriveSymmetricPath(seed, path) {
    return deriveSymmetricPathSync(seed, path);
}
exports.deriveSymmetricPath = deriveSymmetricPath;
function deriveSymmetricPathSync(seed, path) {
    let state = getSymmetricMasterKeyFromSeedSync(seed);
    let remaining = [...path];
    while (remaining.length > 0) {
        let index = remaining[0];
        remaining = remaining.slice(1);
        state = deriveSymmetricHardenedKeySync(state, index);
    }
    return state.key;
}
exports.deriveSymmetricPathSync = deriveSymmetricPathSync;
