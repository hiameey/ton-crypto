/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

export function bytesToBits(bytes: Buffer) {
    return bytes.reduce((str, byte) => str + byte.toString(2).padStart(8, '0'), '')
}

export function bitsToBytes(src: string) {
    if (src.length % 8 !== 0) {
        throw Error('Uneven bits');
    }
    let res: number[] = [];
    while (src.length > 0) {
        res.push(parseInt(src.slice(0, 8), 2));
        src = src.slice(8);
    }
    return Buffer.from(res);
}
