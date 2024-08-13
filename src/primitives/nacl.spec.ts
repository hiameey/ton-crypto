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
        let secretKey = givenSecretKey();
        let data = Buffer.alloc(128, 1);

        let actual = sign(data, secretKey);

        expect(actual.length).toBe(crypto_sign_BYTES)
        expect(actual.toString('hex')).toBe('7ffcf089b9909db2f230dddb0fdcf2f92c538280663cfc3c447a4197824a4dc2b70dae8d60b89c73312c32cd60c82d5051956451b74c5451debfa1c0060cce0b')
    })

    it('should verify signature for given data', () => {
        let pair = keyPairFromSecretKey(givenSecretKey());
        let message = Buffer.alloc(128, 1);
        let signature = Buffer.from('7ffcf089b9909db2f230dddb0fdcf2f92c538280663cfc3c447a4197824a4dc2b70dae8d60b89c73312c32cd60c82d5051956451b74c5451debfa1c0060cce0b', 'hex');

        let actual = signVerify(message, signature, pair.publicKey);

        expect(actual).toBeTruthy()
    })
});


function givenSecretKey(): Buffer {
    return Buffer.from('01010101010101010101010101010101010101010101010101010101010101018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c', 'hex');
}
