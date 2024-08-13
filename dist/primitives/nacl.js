"use strict";
/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.openBox = exports.sealBox = exports.signVerify = exports.sign = exports.keyPairFromSeed = exports.keyPairFromSecretKey = void 0;
const sodium_native_1 = require("sodium-native");
function keyPairFromSecretKey(secretKey) {
    if (secretKey.length !== sodium_native_1.crypto_sign_SECRETKEYBYTES) {
        throw new Error('bad secret key size');
    }
    let publicKey = secretKey.subarray(sodium_native_1.crypto_sign_PUBLICKEYBYTES, sodium_native_1.crypto_sign_SECRETKEYBYTES);
    return {
        publicKey,
        secretKey,
    };
}
exports.keyPairFromSecretKey = keyPairFromSecretKey;
function keyPairFromSeed(seed) {
    if (seed.length !== sodium_native_1.crypto_sign_SEEDBYTES) {
        throw new Error('bad seed size');
    }
    let publicKey = Buffer.alloc(sodium_native_1.crypto_sign_PUBLICKEYBYTES);
    let secretKey = Buffer.alloc(sodium_native_1.crypto_sign_SECRETKEYBYTES);
    (0, sodium_native_1.crypto_sign_seed_keypair)(publicKey, secretKey, seed);
    return {
        publicKey,
        secretKey,
    };
}
exports.keyPairFromSeed = keyPairFromSeed;
function sign(data, secretKey) {
    let signature = Buffer.alloc(sodium_native_1.crypto_sign_BYTES);
    (0, sodium_native_1.crypto_sign_detached)(signature, data, secretKey);
    return signature;
}
exports.sign = sign;
function signVerify(data, signature, publicKey) {
    return (0, sodium_native_1.crypto_sign_verify_detached)(signature, data, publicKey);
}
exports.signVerify = signVerify;
function sealBox(data, nonce, key) {
    if (key.length !== sodium_native_1.crypto_secretbox_KEYBYTES) {
        throw new Error('bad key size');
    }
    if (nonce.length !== sodium_native_1.crypto_secretbox_NONCEBYTES) {
        throw new Error('bad nonce size');
    }
    let ciphertext = Buffer.alloc(data.length + sodium_native_1.crypto_secretbox_MACBYTES);
    (0, sodium_native_1.crypto_secretbox_easy)(ciphertext, data, nonce, key);
    return ciphertext;
}
exports.sealBox = sealBox;
function openBox(ciphertext, nonce, key) {
    if (ciphertext.length < sodium_native_1.crypto_secretbox_MACBYTES) {
        throw new Error('bad ciphertext size');
    }
    if (key.length !== sodium_native_1.crypto_secretbox_KEYBYTES) {
        throw new Error('bad key size');
    }
    if (nonce.length !== sodium_native_1.crypto_secretbox_NONCEBYTES) {
        throw new Error('bad nonce size');
    }
    let data = Buffer.alloc(ciphertext.length - sodium_native_1.crypto_secretbox_MACBYTES);
    if ((0, sodium_native_1.crypto_secretbox_open_easy)(data, ciphertext, nonce, key)) {
        return data;
    }
    return null;
}
exports.openBox = openBox;
