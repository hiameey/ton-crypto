/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import { newSecureWordsSync } from "./newSecureWords";

export async function newSecurePassphrase(size: number = 6): Promise<string> {
    return newSecurePassphraseSync(size)
}

export function newSecurePassphraseSync(size: number = 6): string {
    return newSecureWordsSync(size).join('-')
}
