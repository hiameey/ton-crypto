/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { hmac_sha512_sync } from "../primitives/hmac_sha512";
import { HDKeysState } from "./state";

const ED25519_CURVE = 'ed25519 seed';
const HARDENED_OFFSET = 0x80000000;

export async function getED25519MasterKeyFromSeed(seed: Buffer): Promise<HDKeysState> {
    return getED25519MasterKeyFromSeedSync(seed)
}

export function getED25519MasterKeyFromSeedSync(seed: Buffer): HDKeysState {
    const I = hmac_sha512_sync(ED25519_CURVE, seed);
    const IL = I.slice(0, 32);
    const IR = I.slice(32);

    return {
        key: IL,
        chainCode: IR,
    }
}

export async function deriveED25519HardenedKey(parent: HDKeysState, index: number): Promise<HDKeysState> {
    return deriveED25519HardenedKeySync(parent, index)
}

export function deriveED25519HardenedKeySync(parent: HDKeysState, index: number): HDKeysState {
    if (index >= HARDENED_OFFSET) {
        throw Error('Key index must be less than offset');
    }

    // Key Derive Path: 0x00 + parent.key + index;
    const indexBuffer = Buffer.alloc(4);
    indexBuffer.writeUInt32BE(index + HARDENED_OFFSET, 0);
    const data = Buffer.concat([Buffer.alloc(1, 0), parent.key, indexBuffer]);

    // Derive key
    const I = hmac_sha512_sync(parent.chainCode, data);
    const IL = I.slice(0, 32);
    const IR = I.slice(32);

    return {
        key: IL,
        chainCode: IR,
    }
}

export async function deriveEd25519Path(seed: Buffer, path: number[]): Promise<Buffer> {
    return deriveEd25519PathSync(seed, path)
}

export function deriveEd25519PathSync(seed: Buffer, path: number[]): Buffer {
    let state = getED25519MasterKeyFromSeedSync(seed);
    let remaining = [...path];
    while (remaining.length > 0) {
        let index = remaining[0];
        remaining = remaining.slice(1);
        state = deriveED25519HardenedKeySync(state, index);
    }

    return state.key
}
