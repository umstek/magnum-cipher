package lk.umstek.cryptography.magnum;

import lk.umstek.cryptography.keyderive.Padding;

import java.util.Arrays;
import java.util.Random;

public class Main {

    public static void main(String[] args) {
        testPadding();

        testVigenere();
        testChainedAffineSubstitute();
        testXor();
        testBlockAffinePermute();

        testRoundFunction();
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

    private static void testPadding() {
        Random random = new Random();

        byte[] block = new byte[30];
        random.nextBytes(block);
        byte[] exBlock = Padding.repeatKey(block);

        if (exBlock.length != 32) throw new AssertionError();
        if (exBlock[30] != block[0]) throw new AssertionError();
        if (exBlock[31] != block[1]) throw new AssertionError();

        byte[] block1 = new byte[60];
        random.nextBytes(block1);
        byte[] exBlock1 = Padding.repeatKey(block1);

        if (exBlock1.length != 64) throw new AssertionError();
        if (exBlock1[60] != block1[0]) throw new AssertionError();
        if (exBlock1[61] != block1[1]) throw new AssertionError();
        if (exBlock1[62] != block1[2]) throw new AssertionError();
        if (exBlock1[63] != block1[3]) throw new AssertionError();
    }
}
