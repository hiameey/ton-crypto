import {keyPairFromSecretKey, keyPairFromSeed, sign, signVerify} from "./nacl";
import {
    crypto_sign_BYTES,
    crypto_sign_PUBLICKEYBYTES, crypto_sign_SECRETKEYBYTES, crypto_sign_SEEDBYTES
} from "sodium-native";

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

    it('should return signature for given data', () => {
        let secretKey = Buffer.alloc(crypto_sign_SECRETKEYBYTES, 0);
        let data = Buffer.alloc(128, 1);

        let actual = sign(data, secretKey);

        expect(actual.length).toBe(crypto_sign_BYTES)
        expect(actual.toString('hex')).toBe('5a56c995a84e2093c7e1328b625ebd139298cece9ece29b181235f48e405cead47dbf279419528c5d97408ab1a4a5019448405b88dc0c1bb9bcdd06ecdd19801')
    })

    it('should verify signature for given data', () => {
        let message = Buffer.alloc(128, 1);
        let seed = Buffer.alloc(crypto_sign_SEEDBYTES, 1);
        let pair = keyPairFromSeed(seed);
        let signature = sign(message, pair.secretKey);

        let actual = signVerify(message, signature, pair.publicKey);

        expect(actual).toBeTruthy()
    })
});
