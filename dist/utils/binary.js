"use strict";
/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.bitsToBytes = exports.bytesToBits = void 0;
function bytesToBits(bytes) {
    return bytes.reduce((str, byte) => str + byte.toString(2).padStart(8, '0'), '');
}
exports.bytesToBits = bytesToBits;
function bitsToBytes(src) {
    if (src.length % 8 !== 0) {
        throw Error('Uneven bits');
    }
    let res = [];
    while (src.length > 0) {
        res.push(parseInt(src.slice(0, 8), 2));
        src = src.slice(8);
    }
    return Buffer.from(res);
}
exports.bitsToBytes = bitsToBytes;
