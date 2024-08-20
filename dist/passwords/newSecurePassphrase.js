"use strict";
/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.newSecurePassphraseSync = exports.newSecurePassphrase = void 0;
const newSecureWords_1 = require("./newSecureWords");
async function newSecurePassphrase(size = 6) {
    return newSecurePassphraseSync(size);
}
exports.newSecurePassphrase = newSecurePassphrase;
function newSecurePassphraseSync(size = 6) {
    return (0, newSecureWords_1.newSecureWordsSync)(size).join('-');
}
exports.newSecurePassphraseSync = newSecurePassphraseSync;
