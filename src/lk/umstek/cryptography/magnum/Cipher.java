package lk.umstek.cryptography.magnum;

import java.util.Arrays;

/**
 *
 */
public class Cipher {

    /**
     * A single step consists of following steps.
     * 1. XOR
     * 2. Chained affine substitution
     * 3. Block Affine Permutation
     * 4. Vigenère transform
     *
     * @param key   16-byte round-key
     * @param block 16-byte sub-block
     * @return the given block encrypted with all functions
     */
    static byte[] encryptRound(byte[] key, byte[] block) {
        byte[] partialKey1 = Arrays.copyOfRange(key, 0, 8);
        byte[] partialKey2 = Arrays.copyOfRange(key, 8, 16);

        byte[] xor1 = SBox.xor(true, partialKey1, Arrays.copyOfRange(block, 0, 8));
        byte[] xor2 = SBox.xor(true, partialKey2, Arrays.copyOfRange(block, 8, 16));

        // partial keys are swapped here
        byte[] cas1 = SBox.chainedAffineSubstitute(true, partialKey2, xor1);
        byte[] cas2 = SBox.chainedAffineSubstitute(true, partialKey1, xor2);

        byte[] preBlockAffine = new byte[16]; // combine both
        System.arraycopy(cas1, 0, preBlockAffine, 0, 8);
        System.arraycopy(cas2, 0, preBlockAffine, 8, 8);
        byte[] reversedKey = new byte[16];
        for (int i = 0; i < 16; i++) { // use reversed key for permutation
            reversedKey[16 - i - 1] = key[i];
        }
        byte[] bap = PBox.blockAffinePermute(true, reversedKey, preBlockAffine);

        byte[] v1 = SBox.vigenere(true, partialKey1, Arrays.copyOfRange(bap, 0, 8));
        byte[] v2 = SBox.vigenere(true, partialKey2, Arrays.copyOfRange(bap, 8, 16));

        byte[] out = new byte[16];
        System.arraycopy(v1, 0, out, 0, 8);
        System.arraycopy(v2, 0, out, 8, 8);

        return out;
    }

    /**
     * Reverses the encryption
     *
     * @param key   16-byte round-key
     * @param block 16-byte sub-block
     * @return decrypted block
     */
    static byte[] decryptRound(byte[] key, byte[] block) {
        byte[] partialKey1 = Arrays.copyOfRange(key, 0, 8);
        byte[] partialKey2 = Arrays.copyOfRange(key, 8, 16);

        byte[] v1 = SBox.vigenere(false, partialKey1, Arrays.copyOfRange(block, 0, 8));
        byte[] v2 = SBox.vigenere(false, partialKey2, Arrays.copyOfRange(block, 8, 16));

        byte[] preBlockAffine = new byte[16]; // combine both
        System.arraycopy(v1, 0, preBlockAffine, 0, 8);
        System.arraycopy(v2, 0, preBlockAffine, 8, 8);
        byte[] reversedKey = new byte[16];
        for (int i = 0; i < 16; i++) { // use reversed key for permutation
            reversedKey[16 - i - 1] = key[i];
        }
        byte[] bap = PBox.blockAffinePermute(false, reversedKey, preBlockAffine);

        // partial keys are swapped here
        byte[] cas1 = SBox.chainedAffineSubstitute(false, partialKey2, Arrays.copyOfRange(bap, 0, 8));
        byte[] cas2 = SBox.chainedAffineSubstitute(false, partialKey1, Arrays.copyOfRange(bap, 8, 16));

        byte[] xor1 = SBox.xor(false, partialKey1, cas1);
        byte[] xor2 = SBox.xor(false, partialKey2, cas2);

        byte[] out = new byte[16];
        System.arraycopy(xor1, 0, out, 0, 8);
        System.arraycopy(xor2, 0, out, 8, 8);

        return out;
    }
}
