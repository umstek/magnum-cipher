package lk.umstek.cryptography.util;

import java.util.Arrays;

/**
 *
 */
public class Padding {

    /**
     * Repeat a bytes until it is a multiple of 32.
     * If it is already a multiple of 32, nothing is added.
     * This is not reversible.
     *
     * @param bytes bytes with any length
     * @return extended bytes with a length of multiple of 32
     */
    public static byte[] repeat(byte[] bytes) {
        if (bytes.length % 32 == 0) {
            return bytes;
        }

        if (bytes.length < 32) { // bytes can be fit multiple times into 32
            byte[] extended = new byte[32];
            int q = 32 / bytes.length;
            int r = 32 % bytes.length;

            for (int i = 0; i < q; i++) {
                System.arraycopy(bytes, 0, extended, i * bytes.length, bytes.length);
            }
            System.arraycopy(bytes, 0, extended, q * bytes.length, r);

            return extended;
        }

        byte[] extended = new byte[bytes.length + 32 - bytes.length % 32];
        int r = 32 - bytes.length % 32;

        System.arraycopy(bytes, 0, extended, 0, bytes.length);
        System.arraycopy(bytes, 0, extended, bytes.length, r);

        return extended;
    }

    /**
     * PKCS#7 padding.
     * Adds number of padded bytes as padding symbol until byte count is a multiple of 32.
     * If already a multiple of 32, 32 bytes are padded.
     *
     * @param bytes input
     * @return bytes padded to 32 byte length
     * @see <a href='https://tools.ietf.org/html/rfc5652#section-6.3'>RFC 5652</a>
     */
    public static byte[] pkcs7pad(byte[] bytes) {
        byte fill = (byte) (32 - bytes.length % 32);
        byte[] padded = new byte[bytes.length + fill];
        System.arraycopy(bytes, 0, padded, 0, bytes.length);
        Arrays.fill(padded, bytes.length, bytes.length + fill, fill);
        return padded;
    }

    /**
     * PKCS#7 remove padding.
     *
     * @param bytes
     * @return
     */
    public static byte[] pkcs7unpad(byte[] bytes) {
        byte[] unpadded = new byte[bytes.length - bytes[bytes.length - 1]];
        System.arraycopy(bytes, 0, unpadded, 0, bytes.length - bytes[bytes.length - 1]);
        return unpadded;
    }
}
