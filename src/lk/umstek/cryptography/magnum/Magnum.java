package lk.umstek.cryptography.magnum;

import lk.umstek.cryptography.util.Padding;

import java.util.Random;

/**
 * Entry point for Magnum Cipher
 */
public class Magnum {

    /**
     * Encrypt with Magnum Cipher in CBC mode
     *
     * @param key  Initial binary key
     * @param data Raw data to be encrypted
     * @return IV used for CBC and encrypted data
     */
    public static byte[][] encrypt(byte[] key, byte[] data) {
        key = Padding.repeat(key);
        data = Padding.pkcs7pad(data);
        byte[] iv = new byte[32];
        new Random().nextBytes(iv);

        return new byte[][]{iv, Modes.cbc(true, iv, key, data)};
    }

    /**
     * Decrypts with Magnum Cipher in CBC mode
     *
     * @param iv   Initialization Vector (IV) used in encryption
     * @param key  Initial binary key
     * @param data Encrypted data
     * @return Decrypted data
     */
    public static byte[] decrypt(byte[] iv, byte[] key, byte[] data) {
        key = Padding.repeat(key);

        return Padding.pkcs7unpad(Modes.cbc(false, iv, key, data));
    }
}
