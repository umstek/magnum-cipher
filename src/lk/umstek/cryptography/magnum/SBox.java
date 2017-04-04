package lk.umstek.cryptography.magnum;

/**
 * Created by wickramaranga on 4/4/17.
 */
public class SBox {

    /**
     * @param encrypt    encrypting or decrypting
     * @param partialKey 8-byte partial-key
     * @param block      8-byte sub-block
     * @return
     */
    static byte[] vigenere(boolean encrypt, byte[] partialKey, byte[] block) {
        byte[] out = new byte[8];

        if (encrypt) {
            // Vigenère cipher for Binary
            for (int i = 0; i < 8; i++) {
                // Handle Java's lack of unsigned byte by adding 256
                out[i] = (byte) ((block[i] + partialKey[i] + 256) % 256 - 128);
            }
        } else /* decrypt */ {
            for (int i = 0; i < 8; i++) {
                // Avoid any negative numbers before modulo operation
                out[i] = (byte) ((block[i] - partialKey[i] + 256) % 256 - 128);
            }
        }

        return out;
    }
}
