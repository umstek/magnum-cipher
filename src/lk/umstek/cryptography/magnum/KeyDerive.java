package lk.umstek.cryptography.magnum;

import java.util.Arrays;

/**
 *
 */
public class KeyDerive {

    /**
     * @param fullKey
     * @param roundNumber
     * @return
     */
    public static byte[] nextKey(byte[] fullKey, int roundNumber) {
        if (roundNumber * 32 < fullKey.length) {
            return Arrays.copyOfRange(fullKey, roundNumber * 32, roundNumber * 32 + 32);
        } else {

        }
    }

}
