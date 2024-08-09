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
exports.hmac_sha512 = exports.hmac_sha512_fallback = void 0;
const node_crypto_1 = __importDefault(require("node:crypto"));
async function hmac_sha512_fallback(key, data) {
    return hmac_sha512(key, data);
}
exports.hmac_sha512_fallback = hmac_sha512_fallback;
function hmac_sha512(key, data) {
    let keyBuffer = typeof key === 'string' ? Buffer.from(key, 'utf-8') : key;
    let dataBuffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;
    return Promise.resolve(node_crypto_1.default.createHmac('sha512', keyBuffer)
        .update(dataBuffer)
        .digest());
}
exports.hmac_sha512 = hmac_sha512;
