package lk.umstek.cryptography.magnum;

import static lk.umstek.cryptography.magnum.Constants.PRIMES;

/**
 * Substitutions
 */
public final class SBox {

    /**
     * Byte-wise implementation of classical Vigenère cipher <i>(b_i + k_i) mod m</i>;
     * Where <i>m</i> is the size of the alphabet <i>= 256</i>.
     *
     * @param encrypt encrypting or decrypting
     * @param key     8-byte partial-key
     * @param block   8-byte sub-block
     * @return block encrypted with Vigenère cipher
     */
    static byte[] vigenere(final boolean encrypt, byte[] key, byte[] block) {
        byte[] out = new byte[8];

        if (encrypt) {
            // Vigenère cipher for Binary
            for (int i = 0; i < 8; i++) {
                // Handle Java's lack of unsigned byte by adding 128*2
                out[i] = (byte) ((block[i] + key[i] + 256) % 256 - 128);
            }
        } else /* decrypt */ {
            for (int i = 0; i < 8; i++) {
                // Avoid any negative numbers before modulo operation
                out[i] = (byte) ((block[i] - key[i] + 256) % 256 - 128);
            }
        }

        return out;
    }

    /**
     * A chained byte-wise implementation of classical affine cipher <i>y = (ax + b) mod m</i>.
     *
     * @param encrypt encrypting or decrypting
     * @param key     8-byte partial-key
     * @param block   8-byte sub-block
     * @return block transformed using chained affine cipher
     */
    static byte[] chainedAffineSubstitute(final boolean encrypt, byte[] key, byte[] block) {
        byte[] lookup = new byte[256];

        for (int i = 0; i < 256; i++) {
            int o = i;
            for (int j = 0; j < 4; j++) { // chain affine ciphers
                o = (o * PRIMES[key[j * 2] + 128] + (key[j * 2 + 1] + 128)) % 256;
            }

            if (encrypt) { // create a lookup table for chained affine transform
                lookup[i] = (byte) (o - 128);
            } else /* decrypt */ { // create a lookup table for inverse chained affine transform
                lookup[o] = (byte) (i - 128);
            }
        }

        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) { // perform operation
            out[i] = lookup[block[i] + 128];
        }

        return out;
    }

    /**
     * Directly Bitwise-XOR data block with partial key.
     *
     * @param encrypt encrypting or decrypting
     * @param key     8-byte partial-key
     * @param block   8-byte sub-block
     * @return block XORed with key
     */
    static byte[] xor(final boolean encrypt, byte[] key, byte[] block) {
        byte[] out = new byte[8];

        // encryption and decryption are the same
        for (int i = 0; i < 8; i++) {
            out[i] = (byte) (block[i] ^ key[i]);
        }

        return out;
    }
}
