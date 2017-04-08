package lk.umstek.cryptography.keyderive;

/**
 *
 */
public class Padding {

    /**
     * Repeat a key until it is a multiple of 32
     *
     * @param key key with any length
     * @return extended key with a length of multiple of 32
     */
    public static byte[] repeatKey(byte[] key) {
        if (key.length % 32 == 0) {
            return key;
        }

        if (key.length < 32) { // key can be fit multiple times into 32
            byte[] extendedKey = new byte[32];
            int q = 32 / key.length;
            int r = 32 % key.length;

            for (int i = 0; i < q; i++) {
                System.arraycopy(key, 0, extendedKey, i * key.length, key.length);
            }
            System.arraycopy(key, 0, extendedKey, q * key.length, r);

            return extendedKey;
        }

        byte[] extendedKey = new byte[key.length + 32 - key.length % 32];
        int q = key.length / 32;
        int r = 32 - key.length % 32;

        System.arraycopy(key, 0, extendedKey, 0, key.length);
        System.arraycopy(key, 0, extendedKey, key.length, r);

        return extendedKey;
    }
}
