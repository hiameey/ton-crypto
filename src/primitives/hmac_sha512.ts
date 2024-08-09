/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

import crypto from "node:crypto";

export async function hmac_sha512_fallback(key: string | Buffer, data: string | Buffer): Promise<Buffer> {
    return hmac_sha512(key, data)
}

export function hmac_sha512(key: string | Buffer, data: string | Buffer): Promise<Buffer> {
    let keyBuffer: Buffer = typeof key === 'string' ? Buffer.from(key, 'utf-8') : key;
    let dataBuffer: Buffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;

    return Promise.resolve(
        crypto.createHmac('sha512', keyBuffer)
        .update(dataBuffer)
        .digest()
    );
}
