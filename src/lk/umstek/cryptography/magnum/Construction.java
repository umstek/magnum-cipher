package lk.umstek.cryptography.magnum;

/**
 * Performs cipher rounds for a single block
 */
public final class Construction {

    /**
     * Splits 32-byte array into two same size parts.
     *
     * @param bytes input
     * @return 2 16-byte parts
     */
    private static byte[][] split(byte[] bytes) {
        byte[][] split = new byte[2][16];
        System.arraycopy(bytes, 0, split[0], 0, 16);
        System.arraycopy(bytes, 16, split[1], 0, 16);
        return split;
    }

    /**
     * Encrypts 2 16-byte blocks
     * // FIXME: 4/10/17 change algorithm
     *
     * @param key   2 16-byte encryption keys for each part
     * @param bytes 2 16-byte blocks
     * @return encrypted blocks
     */
    private static byte[][] forward(byte[][] key, byte[][] bytes) {
        byte[][] temp = new byte[2][16];

        temp[0] = Cipher.encryptRound(key[0], bytes[0]);
        temp[1] = Cipher.encryptRound(key[1], bytes[1]);

        return temp;
    }

    /**
     * Decrypts 2 blocks
     * // FIXME: 4/10/17 change algorithm
     *
     * @param key   2 16-byte keys
     * @param bytes 2 16-byte blocks of encrypted bytes
     * @return
     */
    private static byte[][] backward(byte[][] key, byte[][] bytes) {
        byte[][] temp = new byte[2][16];

        temp[0] = Cipher.decryptRound(key[0], bytes[0]);
        temp[1] = Cipher.decryptRound(key[1], bytes[1]);

        return temp;
    }

    /**
     * Combines 2 16-byte arrays into one 32-byte array.
     *
     * @param split 2 arrays
     * @return combined arrays
     */
    private static byte[] combine(byte[][] split) {
        byte[] bytes = new byte[32];
        System.arraycopy(split[0], 0, bytes, 0, 16);
        System.arraycopy(split[1], 0, bytes, 16, 16);
        return bytes;
    }

    /**
     * Process multiple rounds of cipher for a block of data.
     * This is a single step in a mode of operation e.g.: CBC.
     *
     * @param roundCount how many rounds to perform
     * @param encrypt    whether to encrypt or to decrypt
     * @param key        key to use
     * @param block      block to process
     * @return processed block
     */
    public static byte[] processSession(final int roundCount, final boolean encrypt, byte[] key, byte[] block) {
        byte[][] blocks = split(block);

        if (encrypt) {
            for (int i = 0; i < roundCount; i++) {
                byte[][] roundKeys = split(KeyDerive.nextRoundKey(key, i));
                blocks = forward(blocks, roundKeys);
            }
        } else {
            for (int i = 0; i < roundCount; i++) {
                byte[][] roundKeys = split(KeyDerive.nextRoundKey(key, i));
                blocks = backward(blocks, roundKeys);
            }
        }

        return combine(blocks);
    }
}
