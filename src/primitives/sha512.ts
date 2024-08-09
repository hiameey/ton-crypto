/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import crypto from "node:crypto";

export function sha512_sync(source: Buffer | string): Buffer {
    return crypto.createHash('sha512').update(source).digest();
}

export async function sha512_fallback(source: Buffer | string): Promise<Buffer> {
    return Promise.resolve(sha512_sync(source));
}

export async function sha512(source: Buffer | string): Promise<Buffer> {
    return Promise.resolve(sha512_sync(source));
}
