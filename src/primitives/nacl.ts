/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import {
    crypto_secretbox_easy,
    crypto_secretbox_KEYBYTES,
    crypto_secretbox_MACBYTES,
    crypto_secretbox_NONCEBYTES,
    crypto_secretbox_open_easy,
    crypto_sign_BYTES,
    crypto_sign_detached,
    crypto_sign_PUBLICKEYBYTES,
    crypto_sign_SECRETKEYBYTES,
    crypto_sign_seed_keypair,
    crypto_sign_SEEDBYTES,
    crypto_sign_verify_detached
} from 'sodium-native';

export type KeyPair = {
    publicKey: Buffer;
    secretKey: Buffer;
}

export function keyPairFromSecretKey(secretKey: Buffer): KeyPair {
    if (secretKey.length !== crypto_sign_SECRETKEYBYTES) {
        throw new Error('bad secret key size');
    }

    let publicKey = secretKey.subarray(crypto_sign_PUBLICKEYBYTES, crypto_sign_SECRETKEYBYTES);
    return {
        publicKey,
        secretKey,
    }
}

export function keyPairFromSeed(seed: Buffer): KeyPair {
    if (seed.length !== crypto_sign_SEEDBYTES) {
        throw new Error('bad seed size');
    }
    let publicKey = Buffer.alloc(crypto_sign_PUBLICKEYBYTES);
    let secretKey = Buffer.alloc(crypto_sign_SECRETKEYBYTES);

    crypto_sign_seed_keypair(publicKey, secretKey, seed);

    return {
        publicKey,
        secretKey,
    }
}

export function sign(data: Buffer, secretKey: Buffer): Buffer {
    let signature = Buffer.alloc(crypto_sign_BYTES);

    crypto_sign_detached(signature, data, secretKey);

    return signature
}

export function signVerify(data: Buffer, signature: Buffer, publicKey: Buffer) {
    return crypto_sign_verify_detached(signature, data, publicKey)
}

export function sealBox(data: Buffer, nonce: Buffer, key: Buffer) {
    if (key.length !== crypto_secretbox_KEYBYTES) {
        throw new Error('bad key size');
    }
    if (nonce.length !== crypto_secretbox_NONCEBYTES) {
        throw new Error('bad nonce size');
    }

    let ciphertext = Buffer.alloc(data.length + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext, data, nonce, key);

    return ciphertext
}

export function openBox(ciphertext: Buffer, nonce: Buffer, key: Buffer) {
    if (ciphertext.length < crypto_secretbox_MACBYTES) {
        throw new Error('bad ciphertext size');
    }
    if (key.length !== crypto_secretbox_KEYBYTES) {
        throw new Error('bad key size');
    }
    if (nonce.length !== crypto_secretbox_NONCEBYTES) {
        throw new Error('bad nonce size');
    }

    let data = Buffer.alloc(ciphertext.length - crypto_secretbox_MACBYTES);
    if (crypto_secretbox_open_easy(data, ciphertext, nonce, key)) {
        return data;
    }

    return null
}
