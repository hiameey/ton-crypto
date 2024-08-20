/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { getSecureRandomNumberSync } from "../primitives/getSecureRandom";
import { wordlist } from "./wordlist";

export async function newSecureWords(size: number = 6): Promise<string[]> {
    return newSecureWordsSync(size)
}

export function newSecureWordsSync(size: number = 6): string[] {
    let words: string[] = [];
    for (let i = 0; i < size; i++) {
        words.push(wordlist[getSecureRandomNumberSync(0, wordlist.length)]);
    }

    return words;
}
