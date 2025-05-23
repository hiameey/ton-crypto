"use strict";
/**
 * Copyright (c) Whales Corp.
 * All Rights Reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */
Object.defineProperty(exports, "__esModule", { value: true });
const __1 = require("..");
const getSecureRandom_1 = require("../primitives/getSecureRandom");
const mnemonic_1 = require("./mnemonic");
const testVectors = [
    {
        mnemonics: ['hospital', 'stove', 'relief', 'fringe', 'tongue', 'always', 'charge', 'angry', 'urge',
            'sentence', 'again', 'match', 'nerve', 'inquiry', 'senior', 'coconut', 'label', 'tumble',
            'carry', 'category', 'beauty', 'bean', 'road', 'solution'],
        key: '9d659a6c2234db7f6e4f977e6e8653b9f5946d557163f31034011375d8f3f97df6c450a16bb1c514e22f1977e390a3025599aa1e7b00068a6aacf2119484c1bd'
    },
    {
        mnemonics: [
            'dose', 'ice', 'enrich',
            'trigger', 'test', 'dove',
            'century', 'still', 'betray',
            'gas', 'diet', 'dune',
            'use', 'other', 'base',
            'gym', 'mad', 'law',
            'immense', 'village', 'world',
            'example', 'praise', 'game'
        ],
        key: '119dcf2840a3d56521d260b2f125eedc0d4f3795b9e627269a4b5a6dca8257bdc04ad1885c127fe863abb00752fa844e6439bb04f264d70de7cea580b32637ab'
    },
    {
        mnemonics: [
            'hobby', 'coil', 'wisdom',
            'mechanic', 'fossil', 'pretty',
            'enough', 'attract', 'since',
            'choice', 'exhaust', 'hazard',
            'kit', 'oven', 'damp',
            'flip', 'hawk', 'tribe',
            'spice', 'glare', 'step',
            'hammer', 'apple', 'number'
        ],
        key: '764c63ecdc92b331caf3c5a81c483da8444d4ac87d87af9e3cd36ae207d94e5199ac861b19db16bc0f01adfc6897f4760dfc44f9415284c78689d4fcc28b94f7'
    },
    {
        mnemonics: [
            'now', 'wide', 'tag',
            'purity', 'diamond', 'coin',
            'unit', 'rack', 'device',
            'replace', 'cheap', 'deposit',
            'mention', 'fence', 'elite',
            'elder', 'city', 'measure',
            'reward', 'lion', 'chef',
            'promote', 'depart', 'connect'
        ],
        key: '2a8a63e0467f1f4148e0be0cc13e922d726f0b1c29272d6743eb83cf5549128f313abf58635fd310310d1debd54f4fe1fd63631ced044ba0af96b67b85eed31b'
    },
    {
        mnemonics: [
            'clinic', 'toward', 'wedding',
            'category', 'tip', 'spin',
            'purity', 'absent', 'army',
            'gun', 'brain', 'happy',
            'move', 'company', 'that',
            'cheap', 'tank', 'way',
            'shoe', 'awkward', 'pole',
            'protect', 'wear', 'crystal'
        ],
        key: 'e5e78a8e1e509da180bc5aeb8af1a37d4311c5110402842925760a4035119362b1f8a0b9b4c2353ddfad8937ed396fb7670e88e8b72128b15006839a2a86be47'
    }
];
describe('mnemonic', () => {
    it('should generate mnemonics', async () => {
        expect((await (0, __1.mnemonicNew)()).length).toBe(24);
    });
    it('should validate mnemonics', async () => {
        expect(await (0, mnemonic_1.mnemonicValidate)(['a'])).toBe(false);
        expect(await (0, mnemonic_1.mnemonicValidate)([
            'hospital', 'stove', 'relief', 'fringe', 'tongue', 'always', 'charge', 'angry', 'urge',
            'sentence', 'again', 'match', 'nerve', 'inquiry', 'senior', 'coconut', 'label', 'tumble',
            'carry', 'category', 'beauty', 'bean', 'road', 'solution'
        ])).toBe(true);
    });
    for (let i = 0; i < testVectors.length; i++) {
        it('should match vector #' + i, async () => {
            let key = await (0, mnemonic_1.mnemonicToPrivateKey)(testVectors[i].mnemonics);
            let wk = await (0, mnemonic_1.mnemonicToWalletKey)(testVectors[i].mnemonics);
            expect(key.secretKey.toString('hex')).toEqual(testVectors[i].key);
            expect(wk.secretKey.toString('hex')).toEqual(testVectors[i].key);
        });
    }
    it('should generate same keys for mnemonicToPrivateKey and mnemonicToWalletKey', async () => {
        for (let i = 0; i < 10; i++) {
            let k = await (0, __1.mnemonicNew)();
            let key = await (0, mnemonic_1.mnemonicToPrivateKey)(k);
            let wk = await (0, mnemonic_1.mnemonicToWalletKey)(k);
            expect(key.secretKey.toString('hex')).toEqual(wk.secretKey.toString('hex'));
            expect(key.publicKey.toString('hex')).toEqual(wk.publicKey.toString('hex'));
        }
    });
    it('should generate mnemonics from random seed', async () => {
        await (0, mnemonic_1.mnemonicFromRandomSeed)(await (0, getSecureRandom_1.getSecureRandomBytes)(32));
    });
});
