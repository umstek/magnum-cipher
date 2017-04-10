package lk.umstek.cryptography.magnum;

import lk.umstek.cryptography.util.Padding;

import java.util.Arrays;
import java.util.Random;

public class Test {

    public static void main(String[] args) {
        testRepeatPadding();

        testVigenere();
        testChainedAffineSubstitute();
        testXor();
        testBlockAffinePermute();

        testRoundFunction();

        testRoundKeyDerive();

        testSplitCombine();
        testForwardBackward();
        testFWKey();
        testProcessSession();

        testCbc();
    }

    private static void testVigenere() {
        Random random = new Random();

        byte[] block = new byte[8];
        random.nextBytes(block);
        byte[] key1 = new byte[8];
        random.nextBytes(key1);
        byte[] key2 = new byte[8];
        random.nextBytes(key2);

        byte[] sbox1en = SBox.vigenere(true, key1, block);
        byte[] sbox1de = SBox.vigenere(false, key1, sbox1en);
        byte[] sbox1dew = SBox.vigenere(false, key2, sbox1en);
        if (!Arrays.equals(sbox1de, block)) throw new AssertionError();
        if (Arrays.equals(sbox1dew, block)) throw new AssertionError();
    }

    private static void testChainedAffineSubstitute() {
        Random random = new Random();

        byte[] block = new byte[8];
        random.nextBytes(block);
        byte[] key1 = new byte[8];
        random.nextBytes(key1);
        byte[] key2 = new byte[8];
        random.nextBytes(key2);

        byte[] sbox1en = SBox.chainedAffineSubstitute(true, key1, block);
        byte[] sbox1de = SBox.chainedAffineSubstitute(false, key1, sbox1en);
        byte[] sbox1dew = SBox.chainedAffineSubstitute(false, key2, sbox1en);
        if (!Arrays.equals(sbox1de, block)) throw new AssertionError();
        if (Arrays.equals(sbox1dew, block)) throw new AssertionError();
    }

    private static void testXor() {
        Random random = new Random();

        byte[] block = new byte[8];
        random.nextBytes(block);
        byte[] key1 = new byte[8];
        random.nextBytes(key1);
        byte[] key2 = new byte[8];
        random.nextBytes(key2);

        byte[] sbox1en = SBox.xor(true, key1, block);
        byte[] sbox1de = SBox.xor(false, key1, sbox1en);
        byte[] sbox1dew = SBox.xor(false, key2, sbox1en);
        if (!Arrays.equals(sbox1de, block)) throw new AssertionError();
        if (Arrays.equals(sbox1dew, block)) throw new AssertionError();
    }

    private static void testBlockAffinePermute() {
        Random random = new Random();

        byte[] block = new byte[16];
        random.nextBytes(block);
        byte[] key1 = new byte[16];
        random.nextBytes(key1);
        byte[] key2 = new byte[16];
        random.nextBytes(key2);

        byte[] sbox1en = PBox.blockAffinePermute(true, key1, block);
        byte[] sbox1de = PBox.blockAffinePermute(false, key1, sbox1en);
        byte[] sbox1dew = PBox.blockAffinePermute(false, key2, sbox1en);
        if (!Arrays.equals(sbox1de, block)) throw new AssertionError();
        if (Arrays.equals(sbox1dew, block)) throw new AssertionError();
    }

    private static void testRoundKeyDerive() {
        Random random = new Random();

        int r = random.nextInt() % 16 + 1;
        byte[] block = new byte[32];
        random.nextBytes(block);

        final byte[] bytes1 = KeyDerive.nextRoundKey(block, r);
        final byte[] bytes2 = KeyDerive.nextRoundKey(block, r);

        for (int i = 0; i < 32; i++) {
            if (bytes1[i] != bytes2[i]) throw new AssertionError();
        }
    }

    private static void testRoundFunction() {
        Random random = new Random();

        byte[] block = new byte[16];
        random.nextBytes(block);
        byte[] key1 = new byte[16];
        random.nextBytes(key1);
        byte[] key2 = new byte[16];
        random.nextBytes(key2);

        byte[] sbox1en = Cipher.encryptRound(key1, block);
        byte[] sbox1de = Cipher.decryptRound(key1, sbox1en);
        byte[] sbox1dew = Cipher.decryptRound(key2, sbox1en);
        if (!Arrays.equals(sbox1de, block)) throw new AssertionError();
        if (Arrays.equals(sbox1dew, block)) throw new AssertionError();
    }

    private static void testRepeatPadding() {
        Random random = new Random();

        byte[] block = new byte[30];
        random.nextBytes(block);
        byte[] exBlock = Padding.repeat(block);

        if (exBlock.length != 32) throw new AssertionError();
        if (exBlock[30] != block[0]) throw new AssertionError();
        if (exBlock[31] != block[1]) throw new AssertionError();

        byte[] block1 = new byte[60];
        random.nextBytes(block1);
        byte[] exBlock1 = Padding.repeat(block1);

        if (exBlock1.length != 64) throw new AssertionError();
        if (exBlock1[60] != block1[0]) throw new AssertionError();
        if (exBlock1[61] != block1[1]) throw new AssertionError();
        if (exBlock1[62] != block1[2]) throw new AssertionError();
        if (exBlock1[63] != block1[3]) throw new AssertionError();
    }

    private static void testSplitCombine() {
        Random random = new Random();
        byte[] block32 = new byte[32];
        random.nextBytes(block32);

        final byte[][] split = Construction.split(block32);
        final byte[] combine = Construction.combine(split);

        for (int i = 0; i < 32; i++) {
            if (combine[i] != block32[i]) throw new AssertionError();
        }
    }

    private static void testForwardBackward() {
        Random random = new Random();

        byte[] key32 = new byte[32];
        byte[] block32 = new byte[32];
        random.nextBytes(key32);
        random.nextBytes(block32);

        final byte[][] forward = Construction.forward(Construction.split(key32), Construction.split(block32));
        final byte[][] backward = Construction.backward(Construction.split(key32), forward);
        final byte[] combine = Construction.combine(backward);

        for (int i = 0; i < 32; i++) {
            if (combine[i] != block32[i]) throw new AssertionError();
        }
    }

    private static void testFWKey() {
        Random random = new Random();

        int k = random.nextInt() % 16 + 1;
        byte[] key32 = new byte[32];
        byte[] block32 = new byte[32];
        random.nextBytes(key32);
        random.nextBytes(block32);

        final byte[][] forward = Construction.forward(Construction.split(KeyDerive.nextRoundKey(key32, k)), Construction.split(block32));
        final byte[][] backward = Construction.backward(Construction.split(KeyDerive.nextRoundKey(key32, k)), forward);
        final byte[] combine = Construction.combine(backward);

        for (int i = 0; i < 32; i++) {
            if (combine[i] != block32[i]) throw new AssertionError();
        }
    }

    private static void testProcessSession() {
        Random random = new Random();

        int rounds = 2;
        byte[] key32 = new byte[32];
        byte[] block32 = new byte[32];
        random.nextBytes(key32);
        random.nextBytes(block32);

        byte[] enc = Construction.processSession(rounds, true, key32, block32);
        byte[] dec = Construction.processSession(rounds, false, key32, enc);
        for (int i = 0; i < block32.length; i++) {
            if (dec[i] != block32[i]) throw new AssertionError();
        }
    }

    private static void testCbc() {
        Random random = new Random();

        byte[] iv = new byte[32];
        random.nextBytes(iv);
        byte[] key = new byte[256];
        random.nextBytes(key);
        byte[] data = new byte[random.nextInt(1024)];
        random.nextBytes(data);
        data = Padding.pkcs7pad(data);

        final byte[] cbce = Modes.cbc(true, iv, key, data);
        final byte[] cbcd = Modes.cbc(false, iv, key, cbce);

        if (data.length != cbcd.length) throw new AssertionError();

        for (int i = 0; i < cbcd.length; i++) {
            if (cbcd[i] != data[i]) throw new AssertionError();
        }
    }
}
