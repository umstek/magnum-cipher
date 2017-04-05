package lk.umstek.cryptography.magnum;

import java.util.HashMap;
import java.util.Map;

public class SBox {

    /**
     * 256 first primes <b>after</b> 3.
     * Obviously all are relatively prime to 256, to be used in chainAffine.
     */
    private static final int[] PRIMES = {
            5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
            109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227,
            229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
            353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467,
            479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613,
            617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751,
            757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887,
            907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033,
            1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
            1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291,
            1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439,
            1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559,
            1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627
    };

    /**
     * Byte-wise implementation of classical Vigenère cipher <i>(b_i + k_i) mod m</i>;
     * Where <i>m</i> is the size of the alphabet <i>= 256</i>.
     *
     * @param encrypt encrypting or decrypting
     * @param key     8-byte partial-key
     * @param block   8-byte sub-block
     * @return
     */
    static byte[] vigenere(boolean encrypt, byte[] key, byte[] block) {
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
     * @return
     */
    static byte[] chainAffine(boolean encrypt, byte[] key, byte[] block) {
        Map<Byte, Byte> map = new HashMap<>(256);

        for (int i = 0; i < 256; i++) {
            int o = i;
            for (int j = 0; j < 4; j++) { // chain affine ciphers
                o = (o * PRIMES[key[j * 2] + 128] + key[j * 2 + 1]) % 256;
            }

            if (encrypt) { // create a lookup table for chained affine transform
                map.put((byte) (i - 128), (byte) (o - 128));
            } else /* decrypt */ { // create a lookup table for inverse chained affine transform
                map.put((byte) (o - 128), (byte) (i - 128));
            }
        }

        byte[] out = new byte[8];
        for (int i = 0; i < 8; i++) { // perform operation
            out[i] = map.get(block[i]);
        }

        return out;
    }

    /**
     * Directly Bitwise-XOR data block with partial key.
     *
     * @param encrypt encrypting or decrypting
     * @param key     8-byte partial-key
     * @param block   8-byte sub-block
     * @return
     */
    static byte[] xor(boolean encrypt, byte[] key, byte[] block) {
        byte[] out = new byte[8];

        if (encrypt || !encrypt) { // encryption and decryption are the same
            for (int i = 0; i < 8; i++) {
                out[i] = (byte) (block[i] ^ key[i]);
            }
        }

        return out;
    }
}
