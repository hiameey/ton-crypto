import {KeyPair, keyPairFromSecretKey, keyPairFromSeed} from "./nacl";
import {
    crypto_sign_PUBLICKEYBYTES, crypto_sign_SECRETKEYBYTES, crypto_sign_SEEDBYTES
} from "sodium-native";
import nacl from "tweetnacl";

describe('nacl', () => {
    it('should extract public key from secret key', () => {
        let secretKey = Buffer.alloc(crypto_sign_SECRETKEYBYTES, 0);
        secretKey.fill(1, crypto_sign_PUBLICKEYBYTES)
        let expectedPublicKey = Buffer.alloc(crypto_sign_PUBLICKEYBYTES, 1);

        let actual = keyPairFromSecretKey(secretKey);

        expect(actual.secretKey).toEqual(secretKey)
        expect(actual.publicKey).toEqual(expectedPublicKey)
        expect(actual.publicKey.length).toBe(crypto_sign_PUBLICKEYBYTES)
    });

    it('should generate a key pair from a seed', () => {
        let seed = Buffer.alloc(crypto_sign_SEEDBYTES, 1);

        let actual = keyPairFromSeed(seed);

        expect(actual.publicKey.length).toBe(crypto_sign_PUBLICKEYBYTES)
        expect(actual.secretKey.length).toBe(crypto_sign_SECRETKEYBYTES)
    })
});
