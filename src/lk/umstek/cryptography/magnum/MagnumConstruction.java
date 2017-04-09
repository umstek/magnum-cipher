package lk.umstek.cryptography.magnum;

public class MagnumConstruction {

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
     * TODO Change this
     *
     * @param bytes
     * @return
     */
    private static byte[][] forward(byte[] key, byte[][] bytes) {
        byte[][] temp = new byte[2][16];

        temp[0] = Cipher.encryptRound(key, bytes[0]);
        temp[1] = Cipher.encryptRound(key, bytes[1]);

        return temp;
    }

    /**
     * TODO Change this too
     * @param key
     * @param bytes
     * @return
     */
    private static byte[][] backward(byte[] key, byte[][] bytes) {
        byte[][] temp = new byte[2][16];

        temp[0] = Cipher.decryptRound(key, bytes[0]);
        temp[1] = Cipher.decryptRound(key, bytes[1]);

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
}
