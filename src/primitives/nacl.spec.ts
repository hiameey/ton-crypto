import {keyPairFromSecretKey} from "./nacl";
import {
    crypto_scalarmult_BYTES,
    crypto_scalarmult_ed25519_SCALARBYTES,
    crypto_scalarmult_SCALARBYTES, crypto_sign_PUBLICKEYBYTES, crypto_sign_SECRETKEYBYTES
} from "sodium-native";

describe('nacl', () => {
    it('should generate public key based on secret key', () => {
        let secretKey = Buffer.alloc(crypto_sign_SECRETKEYBYTES, 0);
        secretKey.fill(1, crypto_sign_PUBLICKEYBYTES)
        let expectedPublicKey = Buffer.alloc(crypto_sign_PUBLICKEYBYTES, 1);

        let actual = keyPairFromSecretKey(secretKey);

        expect(actual.secretKey).toEqual(secretKey)
        expect(actual.publicKey).toEqual(expectedPublicKey)
        expect(actual.publicKey.length).toBe(crypto_sign_PUBLICKEYBYTES)
    });
});
