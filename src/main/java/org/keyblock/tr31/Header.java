package org.keyblock.tr31;

import org.keyblock.utils.Util;

public class Header {
    private KeyblockType keyBlockYtpe;
    private KeyUsage     keyUsage;
    private Export       export;
    private Algorithm    algorithm;
    private KeyUseFor    keyUseFor;
    private String       version;

    private String       optionalBlock;
    private String       reserved;

    public KeyblockType getKeyBlockType() {
        return keyBlockYtpe;
    }

    public void setKeyBlockYtpe(KeyblockType keyBlockYtpe) {
        this.keyBlockYtpe = keyBlockYtpe;
    }

    public KeyUsage getKeyUsage() {
        return keyUsage;
    }

    public void setKeyUsage(KeyUsage keyUsage) {
        this.keyUsage = keyUsage;
    }

    public Export getExport() {
        return export;
    }

    public void setExport(Export export) {
        this.export = export;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    public KeyUseFor getKeyUseFor() {
        return keyUseFor;
    }

    public void setKeyUseFor(KeyUseFor keyUseFor) {
        this.keyUseFor = keyUseFor;
    }

    public Header(KeyblockType keyBlockYtpe, KeyUsage keyUsage, Export export, Algorithm algorithm, KeyUseFor keyUseFor,
            String version) {
        this.keyBlockYtpe = keyBlockYtpe;
        this.keyUsage = keyUsage;
        this.export = export;
        this.algorithm = algorithm;
        this.keyUseFor = keyUseFor;
        this.version = version;
    }

    public Header(String header) throws Exception {

        int keyBlockLength = Integer.parseInt(header.substring(1, 5));
        // if (keyBlockLength != header.length()) {
        // throw new Exception(String.format(
        // "header keblock length [%d] and received keyblock length [%d] don't match",
        // keyBlockLength,
        // header.length()));
        // }

        keyBlockYtpe = KeyblockType.fromString(header.substring(0, 1))
                                   .get();

        keyUsage = KeyUsage.fromString(header.substring(5, 7))
                           .get();
        algorithm = Algorithm.fromString(header.substring(7, 8))
                             .get();
        keyUseFor = KeyUseFor.fromString(header.substring(8, 9))
                             .get();
        version = header.substring(9, 11);
        export = Export.fromString(header.substring(11, 12))
                       .get();
        optionalBlock = header.substring(12, 14);
        reserved = header.substring(14, 16);
    }

    @Override
    public String toString() {

        StringBuilder temp = new StringBuilder();

        int blocklength = 0;
        int optionalblocks = 0;

        switch (getKeyBlockType()) {
            case _0_THALES_DES:
                blocklength = 16 + optionalblocks + 48 + 8;
                break;
            case _1_THALES_AES:
                blocklength = 16 + optionalblocks + 64 + 16;// #header, optional blocks,key len in ascii, mac
                break;

            case _A_KEY_VARIANT_BINDING:
                // header, optional blocks,encrypted key len in ascii, mac
                // encrypted keylength is length of a triple length 3 DES key (24 bytes) which
                // when transported , its in hex hence its 48
                // e.g. 1 byte 0xC1 represented as string "C1" which is 2 bytes wide.Hence 24
                // bytes is translated to 48.
                blocklength = 16 + optionalblocks + 48 + 8;

                break;
            case _B_TDEA_KEY_DERIVATION_BINDING:

                blocklength = 16 + optionalblocks + 48 + 16;// #header, optional blocks,key len in ascii, mac
                break;
            case _C_TDEA_KEY_VARIANT_BINDING:
                blocklength = 16 + optionalblocks + 48 + 8;
                break;
            case _D_AES_KEY_DERIVATION:
                blocklength = 16 + optionalblocks + 64 + 32;// #header, optional blocks,key len in ascii, mac
                break;

            default:
                break;
        }

        try {
            temp.append(getKeyBlockType().getType())
                .append(Util.padleft(String.valueOf(blocklength), 4, '0'))
                .append(keyUsage.getUsage())
                .append(algorithm.getAlgorithm())
                .append(keyUseFor.get())
                .append(getVersion())
                .append(export.get())
                .append("00") // optional blocks
                .append("00");
            return temp.toString();
        }
        catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

}
