/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import crypto from "node:crypto";

export function hmac_sha512_sync(key: string | Buffer, data: string | Buffer): Buffer {
    let keyBuffer: Buffer = typeof key === 'string' ? Buffer.from(key, 'utf-8') : key;
    let dataBuffer: Buffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;

    return crypto.createHmac('sha512', keyBuffer)
        .update(dataBuffer)
        .digest()
}

export function hmac_sha512(key: string | Buffer, data: string | Buffer): Promise<Buffer> {
    return Promise.resolve(hmac_sha512_sync(key, data));
}

export async function hmac_sha512_fallback(key: string | Buffer, data: string | Buffer): Promise<Buffer> {
    return hmac_sha512(key, data)
}
