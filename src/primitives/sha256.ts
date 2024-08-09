/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import crypto from "node:crypto";

export function sha256_sync(source: Buffer | string): Buffer {
    return crypto.createHash('sha256').update(source).digest();
}

export async function sha256_fallback(source: Buffer | string): Promise<Buffer> {
    return Promise.resolve(sha256_sync(source));
}

export function sha256(source: Buffer | string): Promise<Buffer> {
    return Promise.resolve(sha256_sync(source));
}
