package org.keyblock.tr31;

public enum Algorithm {

                       _A_AES("A"),
                       _D_DEA("D"),
                       _E_ELLIPTIC_CURVE("E"),
                       _H_HMAC_SHA_1("H"),
                       _R_RSA("R"),
                       _S_DSA("S"),
                       _T_TRIPLE_DES("T");

    private String algorithm;

    Algorithm(String al) {
        this.algorithm = al;
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
