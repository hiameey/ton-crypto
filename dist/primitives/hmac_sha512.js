"use strict";
/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.hmac_sha512_fallback = exports.hmac_sha512 = exports.hmac_sha512_sync = void 0;
const node_crypto_1 = __importDefault(require("node:crypto"));
function hmac_sha512_sync(key, data) {
    let keyBuffer = typeof key === 'string' ? Buffer.from(key, 'utf-8') : key;
    let dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    return node_crypto_1.default.createHmac('sha512', keyBuffer)
        .update(dataBuffer)
        .digest();
}
exports.hmac_sha512_sync = hmac_sha512_sync;
async function hmac_sha512(key, data) {
    return hmac_sha512_sync(key, data);
}
exports.hmac_sha512 = hmac_sha512;
async function hmac_sha512_fallback(key, data) {
    return hmac_sha512(key, data);
}
exports.hmac_sha512_fallback = hmac_sha512_fallback;
