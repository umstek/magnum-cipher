package lk.umstek.cryptography.magnum;

import java.util.Arrays;
import java.util.Random;

public class Main {

    public static void main(String[] args) {
        testVigenere();
        testChainedAffineSubstitute();
        testXor();
        testblockAffinePermute();
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

    private static void testblockAffinePermute() {
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
}
