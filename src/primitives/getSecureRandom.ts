/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import * as crypto from "node:crypto";

export async function getSecureRandomBytes(size: number): Promise<Buffer> {
    return crypto.randomBytes(size)
}

export function getSecureRandomBytesSync(size: number): Buffer {
    return crypto.randomBytes(size)
}

export async function getSecureRandomWords(size: number): Promise<Uint16Array> {
    return getSecureRandomWordsSync(size)
}

export function getSecureRandomWordsSync(size: number): Uint16Array {
    let res = new Uint16Array(size);
    crypto.randomFillSync(res);

    return res
}

export async function getSecureRandomNumber(min: number, max: number): Promise<number> {
    return getSecureRandomNumberSync(min, max)
}

export function getSecureRandomNumberSync(min: number, max: number): number {
    if (max > 9007199254740991) {
        throw new Error('Range is too large');
    }

    return crypto.randomInt(min, max)
}
