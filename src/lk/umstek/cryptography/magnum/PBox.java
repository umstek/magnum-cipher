package lk.umstek.cryptography.magnum;

import java.util.Arrays;

import static lk.umstek.cryptography.magnum.Constants.PRIMES;

/**
 * Permutations
 */
public final class PBox {

    /**
     * Applies affine cipher to the indices of rows and columns of a 4*4 matrix
     * in alternating sequence resulting transposition
     *
     * @param encrypt encrypting or decrypting
     * @param key     16-byte partial-key
     * @param block   16-byte sub-block
     * @return alternating row/column affine permutation applied to block
     */
    public static byte[] blockAffinePermute(final boolean encrypt, byte[] key, byte[] block) {
        int[][] lookup = new int[8][4]; // lookup table for row/column transformation
        for (int i = 0; i < 8; i++) { // there are 8 (a, b) pairs for y = (ax + b) mod m transform
            for (int j = 0; j < 4; j++) { // for each row/column, 4 values have to be generated
                if (encrypt) { // lookup
                    lookup[i][j] = (PRIMES[key[i * 2] + 128] * j + (key[i * 2 + 1] + 128)) % 4;
                } else { // reverse-lookup, in reverse sequence
                    lookup[8 - i - 1][(PRIMES[key[i * 2] + 128] * j + (key[i * 2 + 1] + 128)) % 4] = j;
                }
            }
        }

        // byte array = |r|o|w|0|r|o|w|1|r|o|w|2|r|o|w|3
        byte[] out = Arrays.copyOf(block, 16);
        for (int i = 0; i < 8; i++) {
            byte[] temp = new byte[16];
            if (encrypt ^ i % 2 != 0) { // row (since decryption is the reverse operation, odd/even are swapped)
                for (int r = 0; r < 4; r++) {
                    for (int c = 0; c < 4; c++) {
                        temp[r * 4 + c] = out[lookup[i][r] * 4 + c];
                    }
                }
            } else { // column
                for (int r = 0; r < 4; r++) {
                    for (int c = 0; c < 4; c++) {
                        temp[r * 4 + c] = out[r * 4 + lookup[i][c]];
                    }
                }
            }
            out = temp;
        }

        return out;
    }
}
