package lk.umstek.cryptography.magnum;

import java.util.Arrays;

/**
 * Cipher modes of operation
 * // TODO: 4/10/17 add other modes
 */
public class Modes {

    /**
     * Performs cipher-block-chaining mode encryption or decryption
     *
     * @param encrypt    whether to encrypt or decrypt
     * @param paddedKey  binary key which has its length multiple of 32 bytes
     * @param paddedData binary data padded to match multiple-of-32 constraint
     * @return Encrypted data
     */
    public static byte[] cbc(final boolean encrypt, final byte[] iv, byte[] paddedKey, byte[] paddedData) {
        byte[] processed = new byte[paddedData.length];
        int blockCount = paddedData.length / 32;

        if (encrypt) {
            byte[] ciphertext = Arrays.copyOf(iv, 32); // initially IV
            for (int i = 0; i < blockCount; i++) {
                byte[] sessionKey = KeyDerive.nextSessionKey(paddedKey, i);

                byte[] plaintext = Arrays.copyOfRange(paddedData, i * 32, i * 32 + 32);
                for (int j = 0; j < 32; j++) { // XOR plaintext with ciphertext
                    plaintext[j] ^= ciphertext[j];
                }

                ciphertext = Construction.processSession(8, true, sessionKey, plaintext);
                System.arraycopy(ciphertext, 0, processed, i * 32, 32);
            }
        } else /* decrypt */ {
            byte[] output = Arrays.copyOf(iv, 32);
            for (int i = 0; i < blockCount; i++) {
                byte[] sessionKey = KeyDerive.nextSessionKey(paddedKey, i);

                byte[] ciphertext = Arrays.copyOfRange(paddedData, i * 32, i * 32 + 32);
                byte[] plaintext = Construction.processSession(8, false, sessionKey, ciphertext);
                for (int j = 0; j < 32; j++) { // XOR ciphertext with ciphertext
                    plaintext[j] ^= output[j];
                }
                output = ciphertext; // for the next round, this round's ciphertext is needed
                System.arraycopy(plaintext, 0, processed, i * 32, 32);
            }

        }

        return processed;
    }
}
