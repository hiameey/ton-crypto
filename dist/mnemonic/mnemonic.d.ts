/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
/// <reference types="node" />
import { KeyPair } from '../primitives/nacl';
export declare function mnemonicToSeed(mnemonicArray: string[], seed: string, password?: string | null | undefined): Promise<Buffer>;
export declare function mnemonicToSeedSync(mnemonicArray: string[], seed: string, password?: string | null | undefined): Buffer;
/**
 * Extract private key from mnemonic
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns Key Pair
 */
export declare function mnemonicToPrivateKey(mnemonicArray: string[], password?: string | null | undefined): Promise<KeyPair>;
/**
 * Extract private key from mnemonic
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns Key Pair
 */
export declare function mnemonicToPrivateKeySync(mnemonicArray: string[], password?: string | null | undefined): KeyPair;
/**
 * Convert mnemonic to wallet key pair
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns Key Pair
 */
export declare function mnemonicToWalletKey(mnemonicArray: string[], password?: string | null | undefined): Promise<KeyPair>;
/**
 * Convert mnemonic to wallet key pair
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns Key Pair
 */
export declare function mnemonicToWalletKeySync(mnemonicArray: string[], password?: string | null | undefined): KeyPair;
/**
 * Convert mnemonics to HD seed
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns 64 byte seed
 */
export declare function mnemonicToHDSeed(mnemonicArray: string[], password?: string | null | undefined): Promise<Buffer>;
/**
 * Convert mnemonics to HD seed
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns 64 byte seed
 */
export declare function mnemonicToHDSeedSync(mnemonicArray: string[], password?: string | null | undefined): Buffer;
/**
 * Validate Mnemonic
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns true for valid mnemonic
 */
export declare function mnemonicValidate(mnemonicArray: string[], password?: string | null | undefined): Promise<boolean>;
/**
 * Validate Mnemonic
 * @param mnemonicArray mnemonic array
 * @param password mnemonic password
 * @returns true for valid mnemonic
 */
export declare function mnemonicValidateSync(mnemonicArray: string[], password?: string | null | undefined): boolean;
/**
 * Generate new Mnemonic
 * @param wordsCount number of words to generate
 * @param password mnemonic password
 * @returns
 */
export declare function mnemonicNew(wordsCount?: number, password?: string | null | undefined): Promise<string[]>;
/**
 * Generate new Mnemonic
 * @param wordsCount number of words to generate
 * @param password mnemonic password
 * @returns
 */
export declare function mnemonicNewSync(wordsCount?: number, password?: string | null | undefined): string[];
/**
 * Converts bytes to mnemonics array (could be invalid for TON)
 * @param src source buffer
 * @param wordsCount number of words
 */
export declare function bytesToMnemonicIndexes(src: Buffer, wordsCount: number): number[];
export declare function bytesToMnemonics(src: Buffer, wordsCount: number): string[];
/**
 * Generates deterministically mnemonics
 * @param seed
 * @param wordsCount
 * @param password
 */
export declare function mnemonicFromRandomSeed(seed: Buffer, wordsCount?: number, password?: string | null | undefined): string[];
