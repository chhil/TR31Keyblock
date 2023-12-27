package org.keyblock.tr31;

import java.util.Optional;

public enum Algorithm {

                       _A_AES("A"),
                       _D_DEA("D"),
                       _E_ELLIPTIC_CURVE("E"),
                       _H_HMAC("H"),
                       _R_RSA("R"),
                       _S_DSA("S"),
                       _T_TRIPLE_DES("T");

    private final String algorithm;

    Algorithm(String al) {
        this.algorithm = al;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public static Optional<Algorithm> fromString(String algorithm) {

        // iterate over enums using for loop
        for (Algorithm s : Algorithm.values()) {
            if (algorithm.equals(s.getAlgorithm())) {
                return Optional.of(s);
            }
        }
        return Optional.empty();

    }
}
