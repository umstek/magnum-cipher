package lk.umstek.cryptography.magnum;

import java.util.Arrays;

/**
 * Class for multipurpose key generation
 */
public class KeyDerive {

    /**
     * Generates a new key for session
     *
     * @param fullKey     Full key derived directly from the password or any means
     * @param roundNumber The position of the new session key generated
     * @return next session key
     */
    public static byte[] nextSessionKey(byte[] fullKey, final int roundNumber) {
        int times = roundNumber * 32 / fullKey.length;
        int start = roundNumber * 32 % fullKey.length;
        int end = start + 32;

        byte[] key = Arrays.copyOfRange(fullKey, start, end);
        for (int i = 0; i < times; i++) {
            byte[] newKey = new byte[32];
            for (int j = 0; j < 4; j++) {
                byte[] k = Arrays.copyOfRange(key, ((j + 1) % 4) * 8, ((j + 1) % 4) * 8 + 8);
                byte[] b = Arrays.copyOfRange(key, (j % 4) * 8, ((j % 4) * 8) + 8);
                byte[] e = SBox.chainedAffineSubstitute(true, k, b);
                System.arraycopy(e, 0, newKey, j * 8, 8);
            }
            key = newKey;
        }

        return key;
    }

    /**
     * Generates a new key for round
     *
     * @param sessionKey  Key derived for the session
     * @param roundNumber Index of the round being processed
     * @return
     */
    public static byte[] nextRoundKey(byte[] sessionKey, final int roundNumber) {
        int times = roundNumber * 32 / sessionKey.length;
        int start = roundNumber * 32 % sessionKey.length;
        int end = start + 32;

        byte[] key = Arrays.copyOfRange(sessionKey, start, end);
        for (int i = 0; i < times; i++) {
            byte[] newKey = new byte[32];
            for (int j = 0; j < 2; j++) {
                byte[] k = Arrays.copyOfRange(key, ((j + 1) % 2) * 16, ((j + 1) % 2) * 16 + 16);
                byte[] b = Arrays.copyOfRange(key, (j % 2) * 16, ((j % 2) * 16) + 16);
                byte[] e = PBox.blockAffinePermute(true, k, b);
                System.arraycopy(e, 0, newKey, j * 16, 16);
            }
            key = newKey;
        }

        return key;
    }

}
