import { keyPairFromSecretKey, keyPairFromSeed, openBox, sealBox, sign, signVerify } from "./nacl";
import {
    crypto_secretbox_KEYBYTES,
    crypto_secretbox_NONCEBYTES,
    crypto_sign_BYTES,
    crypto_sign_PUBLICKEYBYTES, crypto_sign_SECRETKEYBYTES, crypto_sign_SEEDBYTES
} from "sodium-native";

describe('nacl', () => {
    it('should extract public key from secret key', () => {
        let secretKey = Buffer.alloc(crypto_sign_SECRETKEYBYTES, 0);
        secretKey.fill(1, crypto_sign_PUBLICKEYBYTES);
        let expectedPublicKey = Buffer.alloc(crypto_sign_PUBLICKEYBYTES, 1);

        let actual = keyPairFromSecretKey(secretKey);

        expect(actual.secretKey).toEqual(secretKey);
        expect(actual.publicKey).toEqual(expectedPublicKey);
        expect(actual.publicKey.length).toBe(crypto_sign_PUBLICKEYBYTES);
    });

    it('should generate a key pair from a seed', () => {
        let seed = Buffer.alloc(crypto_sign_SEEDBYTES, 1);

        let actual = keyPairFromSeed(seed);

        expect(actual.publicKey.length).toBe(crypto_sign_PUBLICKEYBYTES);
        expect(actual.secretKey.length).toBe(crypto_sign_SECRETKEYBYTES);
    });

    it('should return signature for given data', () => {
        let secretKey = givenSecretKey();
        let data = Buffer.alloc(128, 1);

        let actual = sign(data, secretKey);

        expect(actual.length).toBe(crypto_sign_BYTES);
        expect(actual.toString('hex')).toBe('7ffcf089b9909db2f230dddb0fdcf2f92c538280663cfc3c447a4197824a4dc2b70dae8d60b89c73312c32cd60c82d5051956451b74c5451debfa1c0060cce0b');
    });

    it('should verify signature for given data', () => {
        let pair = keyPairFromSecretKey(givenSecretKey());
        let message = Buffer.alloc(128, 1);
        let signature = Buffer.from('7ffcf089b9909db2f230dddb0fdcf2f92c538280663cfc3c447a4197824a4dc2b70dae8d60b89c73312c32cd60c82d5051956451b74c5451debfa1c0060cce0b', 'hex');

        let actual = signVerify(message, signature, pair.publicKey);

        expect(actual).toBeTruthy();
    });

    it('should seal message', () => {
        let data = Buffer.alloc(128, 1);
        let nonce = Buffer.alloc(crypto_secretbox_NONCEBYTES, 2);
        let key = Buffer.alloc(crypto_secretbox_KEYBYTES, 3);

        let actual = sealBox(data, nonce, key);

        expect(actual.length).toBe(144);
        expect(actual.toString('hex')).toBe('63c0ff852082e9fcf286cc62d86cdf01115eb5c26388cb3803d0b28d0d3c6ffa4b0fc1c03895978a57771c969d17bbfce3f27ff621560ba22bf7530091632e297f562e82564fb40d100551bc42a3884e8c65f445c6548d60610f38d034dd0a8010970173094767f8ec21c03710515940f00b662c54833d1170195257c55ee28a0860f76c3fd198e44e0b70bc909d4c29');
    });

    it('should open box', () => {
        let data = Buffer.from('63c0ff852082e9fcf286cc62d86cdf01115eb5c26388cb3803d0b28d0d3c6ffa4b0fc1c03895978a57771c969d17bbfce3f27ff621560ba22bf7530091632e297f562e82564fb40d100551bc42a3884e8c65f445c6548d60610f38d034dd0a8010970173094767f8ec21c03710515940f00b662c54833d1170195257c55ee28a0860f76c3fd198e44e0b70bc909d4c29', 'hex');
        let nonce = Buffer.alloc(crypto_secretbox_NONCEBYTES, 2);
        let key = Buffer.alloc(crypto_secretbox_KEYBYTES, 3);

        let actual = openBox(data, nonce, key)!;

        expect(actual.length).toBe(128);
        expect(actual.toString('hex')).toBe(Buffer.alloc(128, 1).toString('hex'));
    });
});


function givenSecretKey(): Buffer {
    return Buffer.from('01010101010101010101010101010101010101010101010101010101010101018a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c', 'hex');
}
