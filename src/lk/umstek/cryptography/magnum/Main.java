package lk.umstek.cryptography.magnum;

import java.util.Arrays;

public class Main {

    public static void main(String[] args) {
        byte[] block = {0, 5, -7, 6, 99, 13, 28, -120};
        byte[] key1 = {1, 2, -52, 98, 79, -9, 126, 0};
        byte[] key2 = {1, 2, -52, 98, 79, -9, 124, 0};
        byte[] sbox1en = SBox.vigenere(true, key1, block);
        byte[] sbox1de = SBox.vigenere(false, key1, sbox1en);
        byte[] sbox1dew = SBox.vigenere(false, key2, sbox1en);
        if (!Arrays.equals(sbox1de, block)) throw new AssertionError();
        if (Arrays.equals(sbox1dew, block)) throw new AssertionError();
    }
}
