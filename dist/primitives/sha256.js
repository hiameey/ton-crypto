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
exports.sha256 = exports.sha256_fallback = exports.sha256_sync = void 0;
const node_crypto_1 = __importDefault(require("node:crypto"));
function sha256_sync(source) {
    return node_crypto_1.default.createHash('sha256').update(source).digest();
}
exports.sha256_sync = sha256_sync;
async function sha256_fallback(source) {
    return Promise.resolve(sha256_sync(source));
}
exports.sha256_fallback = sha256_fallback;
function sha256(source) {
    return Promise.resolve(sha256_sync(source));
}
exports.sha256 = sha256;
