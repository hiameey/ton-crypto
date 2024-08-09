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
exports.sha512 = exports.sha512_fallback = exports.sha512_sync = void 0;
const node_crypto_1 = __importDefault(require("node:crypto"));
function sha512_sync(source) {
    return node_crypto_1.default.createHash('sha512').update(source).digest();
}
exports.sha512_sync = sha512_sync;
async function sha512_fallback(source) {
    return Promise.resolve(sha512_sync(source));
}
exports.sha512_fallback = sha512_fallback;
async function sha512(source) {
    return Promise.resolve(sha512_sync(source));
}
exports.sha512 = sha512;
