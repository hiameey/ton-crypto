"use strict";
/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.mnemonicFromRandomSeed = exports.bytesToMnemonics = exports.bytesToMnemonicIndexes = exports.mnemonicNewSync = exports.mnemonicNew = exports.mnemonicValidateSync = exports.mnemonicValidate = exports.mnemonicToHDSeedSync = exports.mnemonicToHDSeed = exports.mnemonicToWalletKeySync = exports.mnemonicToWalletKey = exports.mnemonicToPrivateKeySync = exports.mnemonicToPrivateKey = exports.mnemonicToSeedSync = exports.mnemonicToSeed = void 0;
const getSecureRandom_1 = require("../primitives/getSecureRandom");
const hmac_sha512_1 = require("../primitives/hmac_sha512");
const nacl_1 = require("../primitives/nacl");
const pbkdf2_sha512_1 = require("../primitives/pbkdf2_sha512");
const binary_1 = require("../utils/binary");
const wordlist_1 = require("./wordlist");
const PBKDF_ITERATIONS = 100000;
async function mnemonicToSeed(mnemonicArray, seed, password) {
    return mnemonicToSeedSync(mnemonicArray, seed, password);
}
exports.mnemonicToSeed = mnemonicToSeed;
function mnemonicToSeedSync(mnemonicArray, seed, password) {
    // https://github.com/ton-blockchain/ton/blob/24dc184a2ea67f9c47042b4104bbb4d82289fac1/tonlib/tonlib/keys/Mnemonic.cpp#L58
    // td::SecureString Mnemonic::to_seed() const {
    //   td::SecureString hash(64);
    //   td::pbkdf2_sha512(as_slice(to_entropy()), "TON default seed", PBKDF_ITERATIONS, hash.as_mutable_slice());
    //   return hash;
    // }
    const entropy = mnemonicToEntropy(mnemonicArray, password);
    return (0, pbkdf2_sha512_1.pbkdf2_sha512_sync)(entropy, seed, PBKDF_ITERATIONS, 64);
}
exports.mnemonicToSeedSync = mnemonicToSeedSync;
/**
 * Extract private key from mnemonic
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns Key Pair
 */
async function mnemonicToPrivateKey(mnemonicArray, password) {
    return mnemonicToPrivateKeySync(mnemonicArray, password);
}
exports.mnemonicToPrivateKey = mnemonicToPrivateKey;
/**
 * Extract private key from mnemonic
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns Key Pair
 */
function mnemonicToPrivateKeySync(mnemonicArray, password) {
    // https://github.com/ton-blockchain/ton/blob/24dc184a2ea67f9c47042b4104bbb4d82289fac1/tonlib/tonlib/keys/Mnemonic.cpp#L64
    // td::Ed25519::PrivateKey Mnemonic::to_private_key() const {
    //   return td::Ed25519::PrivateKey(td::SecureString(as_slice(to_seed()).substr(0, td::Ed25519::PrivateKey::LENGTH)));
    // }
    mnemonicArray = normalizeMnemonic(mnemonicArray);
    const seed = mnemonicToSeedSync(mnemonicArray, 'TON default seed', password);
    return (0, nacl_1.keyPairFromSeed)(seed.subarray(0, 32));
}
exports.mnemonicToPrivateKeySync = mnemonicToPrivateKeySync;
/**
 * Convert mnemonic to wallet key pair
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns Key Pair
 */
async function mnemonicToWalletKey(mnemonicArray, password) {
    return mnemonicToWalletKeySync(mnemonicArray, password);
}
exports.mnemonicToWalletKey = mnemonicToWalletKey;
/**
 * Convert mnemonic to wallet key pair
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns Key Pair
 */
function mnemonicToWalletKeySync(mnemonicArray, password) {
    let seedPk = mnemonicToPrivateKeySync(mnemonicArray, password);
    let seedSecret = seedPk.secretKey.subarray(0, 32);
    return (0, nacl_1.keyPairFromSeed)(seedSecret);
}
exports.mnemonicToWalletKeySync = mnemonicToWalletKeySync;
/**
 * Convert mnemonics to HD seed
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns 64 byte seed
 */
async function mnemonicToHDSeed(mnemonicArray, password) {
    return mnemonicToHDSeedSync(mnemonicArray, password);
}
exports.mnemonicToHDSeed = mnemonicToHDSeed;
/**
 * Convert mnemonics to HD seed
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns 64 byte seed
 */
function mnemonicToHDSeedSync(mnemonicArray, password) {
    mnemonicArray = normalizeMnemonic(mnemonicArray);
    return mnemonicToSeedSync(mnemonicArray, 'TON HD Keys seed', password);
}
exports.mnemonicToHDSeedSync = mnemonicToHDSeedSync;
/**
 * Validate Mnemonic
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns true for valid mnemonic
 */
async function mnemonicValidate(mnemonicArray, password) {
    return mnemonicValidateSync(mnemonicArray, password);
}
exports.mnemonicValidate = mnemonicValidate;
/**
 * Validate Mnemonic
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns true for valid mnemonic
 */
function mnemonicValidateSync(mnemonicArray, password) {
    mnemonicArray = normalizeMnemonic(mnemonicArray);
    // Validate mnemonic words
    for (let word of mnemonicArray) {
        if (wordlist_1.wordlist.indexOf(word) < 0) {
            return false;
        }
    }
    // Check password
    if (password && password.length > 0) {
        if (!isPasswordNeeded(mnemonicArray)) {
            return false;
        }
    }
    // Validate seed
    return isBasicSeed(mnemonicToEntropy(mnemonicArray, password));
}
exports.mnemonicValidateSync = mnemonicValidateSync;
/**
 * Generate new Mnemonic
 * @param wordsCount number of words to generate
 * @param password mnemonic password
 * @returns
 */
async function mnemonicNew(wordsCount = 24, password) {
    return mnemonicNewSync(wordsCount, password);
}
exports.mnemonicNew = mnemonicNew;
/**
 * Generate new Mnemonic
 * @param wordsCount number of words to generate
 * @param password mnemonic password
 * @returns
 */
function mnemonicNewSync(wordsCount = 24, password) {
    // https://github.com/ton-blockchain/ton/blob/24dc184a2ea67f9c47042b4104bbb4d82289fac1/tonlib/tonlib/keys/Mnemonic.cpp#L159
    let mnemonicArray = [];
    while (true) {
        // Regenerate new mnemonics
        mnemonicArray = [];
        for (let i = 0; i < wordsCount; i++) {
            let ind = (0, getSecureRandom_1.getSecureRandomNumberSync)(0, wordlist_1.wordlist.length);
            mnemonicArray.push(wordlist_1.wordlist[ind]);
        }
        // Chek password conformance
        if (password && password.length > 0) {
            if (!isPasswordNeeded(mnemonicArray)) {
                continue;
            }
        }
        // Check if basic seed correct
        if (!(isBasicSeed(mnemonicToEntropy(mnemonicArray, password)))) {
            continue;
        }
        break;
    }
    return mnemonicArray;
}
exports.mnemonicNewSync = mnemonicNewSync;
/**
 * Converts bytes to mnemonics array (could be invalid for TON)
 * @param src source buffer
 * @param wordsCount number of words
 */
function bytesToMnemonicIndexes(src, wordsCount) {
    let bits = (0, binary_1.bytesToBits)(src);
    let indexes = [];
    for (let i = 0; i < wordsCount; i++) {
        let sl = bits.slice(i * 11, i * 11 + 11);
        indexes.push(parseInt(sl, 2));
    }
    return indexes;
}
exports.bytesToMnemonicIndexes = bytesToMnemonicIndexes;
function bytesToMnemonics(src, wordsCount) {
    let mnemonics = bytesToMnemonicIndexes(src, wordsCount);
    let res = [];
    for (let m of mnemonics) {
        res.push(wordlist_1.wordlist[m]);
    }
    return res;
}
exports.bytesToMnemonics = bytesToMnemonics;
/**
 * Converts mnemonics indexes to buffer with zero padding in the end
 * @param src source indexes
 * @returns Buffer
 */
function mnemonicIndexesToBytes(src) {
    let res = '';
    for (let s of src) {
        if (!Number.isSafeInteger(s)) {
            throw Error('Invalid input');
        }
        if (s < 0 || s >= 2028) {
            throw Error('Invalid input');
        }
        res += s.toString(2).padStart(11, '0');
    }
    while (res.length % 8 !== 0) {
        res = res + '0';
    }
    return (0, binary_1.bitsToBytes)(res);
}
/**
 * Generates deterministically mnemonics
 * @param seed
 * @param wordsCount
 * @param password
 */
function mnemonicFromRandomSeed(seed, wordsCount = 24, password) {
    const bytesLength = Math.ceil(wordsCount * 11 / 8);
    let currentSeed = seed;
    while (true) {
        // Create entropy
        let entropy = (0, pbkdf2_sha512_1.pbkdf2_sha512_sync)(currentSeed, 'TON mnemonic seed', Math.max(1, Math.floor(PBKDF_ITERATIONS / 256)), bytesLength);
        // Create mnemonics
        let mnemonics = bytesToMnemonics(entropy, wordsCount);
        // Check if mnemonics are valid
        if (mnemonicValidateSync(mnemonics, password)) {
            return mnemonics;
        }
        currentSeed = entropy;
    }
}
exports.mnemonicFromRandomSeed = mnemonicFromRandomSeed;
function isPasswordNeeded(mnemonicArray) {
    const passlessEntropy = mnemonicToEntropy(mnemonicArray);
    return isPasswordSeed(passlessEntropy) && !isBasicSeed(passlessEntropy);
}
function normalizeMnemonic(src) {
    return src.map((v) => v.toLowerCase().trim());
}
function isBasicSeed(entropy) {
    // https://github.com/ton-blockchain/ton/blob/24dc184a2ea67f9c47042b4104bbb4d82289fac1/tonlib/tonlib/keys/Mnemonic.cpp#L68
    // bool Mnemonic::is_basic_seed() {
    //   td::SecureString hash(64);
    //   td::pbkdf2_sha512(as_slice(to_entropy()), "TON seed version", td::max(1, PBKDF_ITERATIONS / 256),
    //                     hash.as_mutable_slice());
    //   return hash.as_slice()[0] == 0;
    // }
    const seed = (0, pbkdf2_sha512_1.pbkdf2_sha512_sync)(entropy, 'TON seed version', Math.max(1, Math.floor(PBKDF_ITERATIONS / 256)), 64);
    return seed[0] == 0;
}
function isPasswordSeed(entropy) {
    // https://github.com/ton-blockchain/ton/blob/24dc184a2ea67f9c47042b4104bbb4d82289fac1/tonlib/tonlib/keys/Mnemonic.cpp#L75
    // bool Mnemonic::is_password_seed() {
    //   td::SecureString hash(64);
    //   td::pbkdf2_sha512(as_slice(to_entropy()), "TON fast seed version", 1, hash.as_mutable_slice());
    //   return hash.as_slice()[0] == 1;
    // }
    const seed = (0, pbkdf2_sha512_1.pbkdf2_sha512_sync)(entropy, 'TON fast seed version', 1, 64);
    return seed[0] == 1;
}
function mnemonicToEntropy(mnemonicArray, password) {
    // https://github.com/ton-blockchain/ton/blob/24dc184a2ea67f9c47042b4104bbb4d82289fac1/tonlib/tonlib/keys/Mnemonic.cpp#L52
    // td::SecureString Mnemonic::to_entropy() const {
    //   td::SecureString res(64);
    //   td::hmac_sha512(join(words_), password_, res.as_mutable_slice());
    //   return res;
    // }
    return (0, hmac_sha512_1.hmac_sha512_sync)(mnemonicArray.join(' '), password && password.length > 0 ? password : '');
}
