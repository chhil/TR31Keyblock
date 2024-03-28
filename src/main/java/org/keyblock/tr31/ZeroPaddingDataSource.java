package org.keyblock.tr31;

import java.util.Arrays;

/**
 * Insecure source padding data source supplies all zeros. Used by default.
 */
public class ZeroPaddingDataSource implements PaddingDataSource {

    @Override
    public void nextBytes(byte[] buf) {
        Arrays.fill(buf, (byte) 0);
    }
}
