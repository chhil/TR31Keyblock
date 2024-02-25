package org.keyblock.tr31;

import java.security.SecureRandom;

/**
 * Secure random padding data source.
 */
public class SecureRandomPaddingDataSource implements PaddingDataSource {

    final SecureRandom sr = new SecureRandom();

    @Override
    public void nextBytes(byte[] buf) {
        sr.nextBytes(buf);
    }
}
