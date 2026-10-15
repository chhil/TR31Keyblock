package org.keyblock.tr31;

import org.keyblock.utils.Util;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class Header {

    private KeyblockType keyBlockType;
    private int          keyBlockLength;
    private KeyUsage     keyUsage;
    private Export       export;
    private Algorithm    algorithm;
    private KeyUseFor    keyUseFor;
    private String       version;
    private int          numOptionalBlocks;
    private String       reserved = "00";

    private List<OptionalBlock> optionalBlockList = new LinkedList<>();

    /**
     * ANSI X9.143:2021 A.5.6: an optional block ID value cannot be repeated within a key block.
     */
    private final java.util.Set<String> optionalBlockIdsSeen = new java.util.HashSet<>();

    public KeyblockType getKeyBlockType() {
        return keyBlockType;
    }

    public void setKeyBlockType(KeyblockType keyBlockType) {
        this.keyBlockType = keyBlockType;
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

    /**
     * After using this constructor it is necessary to invoke {@link #updateKeyBlockLength(int)}
     * to populate the key block length.
     */
    public Header(KeyblockType keyBlockType, KeyUsage keyUsage, Export export, Algorithm algorithm, KeyUseFor keyUseFor,
            String version) {
        this.keyBlockType = keyBlockType;
        this.keyUsage = keyUsage;
        this.export = export;
        this.algorithm = algorithm;
        this.keyUseFor = keyUseFor;
        this.version = version;
    }

    /**
     * This may be the truncated header string or the entire key block.
     */
    public Header(String header) {
        this(header, false);
    }

    /**
     * @param strictOptionalBlockData
     *            when true the data of each optional block with a defined ID is checked
     *            against the character format the standard requires for it, otherwise
     *            only the structure of the optional block is checked
     */
    public Header(String header, boolean strictOptionalBlockData) {
        KeyBlockValidation.validateHeader(header);

        keyBlockType = KeyblockType.fromString(header.substring(0, 1))
                                 .orElseThrow(() -> new IllegalArgumentException(
                                         "Unsupported key block version ID '" + header.substring(0, 1) + "'"));
        keyBlockLength = Integer.parseInt(header.substring(1, 5));
        keyUsage = KeyUsage.fromString(header.substring(5, 7))
                           .orElseThrow(() -> new IllegalArgumentException(
                                   "Unsupported key usage '" + header.substring(5, 7) + "'"));
        algorithm = Algorithm.fromString(header.substring(7, 8))
                             .orElseThrow(() -> new IllegalArgumentException(
                                     "Unsupported algorithm '" + header.substring(7, 8) + "'"));
        keyUseFor = KeyUseFor.fromString(header.substring(8, 9))
                             .orElseThrow(() -> new IllegalArgumentException(
                                     "Unsupported mode of use '" + header.substring(8, 9) + "'"));
        version = header.substring(9, 11);
        export = Export.fromString(header.substring(11, 12))
                       .orElseThrow(() -> new IllegalArgumentException(
                               "Unsupported exportability '" + header.substring(11, 12) + "'"));
        numOptionalBlocks = Integer.parseInt(header.substring(12, 14));
        reserved = header.substring(14, 16);

        int pos = 16;

        for (int i = 0; i < numOptionalBlocks; i++) {
            String obId = readField(header, pos, 2, "optional block ID");
            pos += 2;
            KeyBlockValidation.validateOptionalBlockId(obId);
            if (optionalBlockIdsSeen.contains(obId)) {
                throw new IllegalArgumentException(
                        "Optional block ID '" + obId + "' appears more than once");
            }
            optionalBlockIdsSeen.add(obId);

            int obDataLen;
            int obLen = readHexField(header, pos, 2, "optional block '" + obId + "' length");
            pos += 2;
            if (obLen == 0) {
                int obLenOfLen = readHexField(header, pos, 2, "optional block '" + obId + "' length of length");
                pos += 2;
                if (obLenOfLen == 0) {
                    throw new IllegalArgumentException(
                            "Optional block '" + obId + "' length of length must not be zero, at position " + pos);
                }

                obLen = readHexField(header, pos, obLenOfLen, "optional block '" + obId + "' extended length");
                pos += obLenOfLen;
                // ID (2) + length field (2) + length of length field (2) + the length field
                // itself, see ANSI X9.143:2021 A.5.6
                obDataLen = obLen - 2 - 2 - 2 - obLenOfLen;
            } else {
                obDataLen = obLen - 2 - 2;
            }

            if (obDataLen < 0 || pos + obDataLen > header.length()) {
                throw new IllegalArgumentException("Optional block '" + obId + "' declares an invalid length "
                        + obLen);
            }

            String obData = header.substring(pos, pos += obDataLen);
            KeyBlockValidation.validateOptionalBlock(obId, obData, strictOptionalBlockData);
            optionalBlockList.add(new OptionalBlock(obId, obData));
        }

        setOptionalBlockList(optionalBlockList);
    }

    /**
     * A field of a key block, bounded before it is sliced. A header that is truncated in the middle
     * of its optional blocks then fails as an IllegalArgumentException, the same as every other
     * rejection in the constructor, rather than as a StringIndexOutOfBoundsException.
     */
    private static String readField(String header, int offset, int length, String what) {
        if (length < 0 || offset < 0 || offset + length > header.length()) {
            throw new IllegalArgumentException("The " + what + " of " + length
                    + " characters does not fit at position " + offset + " of a header of "
                    + header.length() + " characters");
        }
        return header.substring(offset, offset + length);
    }

    /**
     * A field of a key block that carries a number as hexadecimal ASCII.
     */
    private static int readHexField(String header, int offset, int length, String what) {
        String field = readField(header, offset, length, what);
        try {
            return Integer.parseInt(field, 16);
        }
        catch (NumberFormatException e) {
            // a length field wide enough to overflow an int, or one holding a non hex character
            throw new IllegalArgumentException(
                    "The " + what + " '" + field + "' is not a hexadecimal number");
        }
    }

    @Override
    public String toString() {
        StringBuilder temp = new StringBuilder(16);
        temp.append(getKeyBlockType().getType())
            .append(Util.padLeft(String.valueOf(keyBlockLength), 4, '0'))
            .append(keyUsage.getUsage())
            .append(algorithm.getAlgorithm())
            .append(keyUseFor.get())
            .append(getVersion())
            .append(export.get())
            .append(Util.padLeft(String.valueOf(numOptionalBlocks), 2, '0'))
            .append(reserved)
            .append(buildOptBlocksString());

        return temp.toString();
    }

    /**
     * The optional blocks of this header, in the order they appear.
     */
    public List<OptionalBlock> getOptionalBlocks() {
        return Collections.unmodifiableList(optionalBlockList);
    }

    /**
     * The first optional block with the given ID, or null when the header does not carry it.
     */
    public OptionalBlock getOptionalBlock(String id) {
        for (OptionalBlock ob : optionalBlockList) {
            if (ob.getId()
                   .equals(id)) {
                return ob;
            }
        }
        return null;
    }

    private String buildOptBlocksString() {
        StringBuilder temp = new StringBuilder();
        for (OptionalBlock ob : optionalBlockList) {
            temp.append(ob.toString());
        }
        return temp.toString();
    }

    private String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Return the length of this header only.
     */
    public int getLength() {
        return toString().length();
    }

    /**
     * Return the length of the entire key block including the header. May return 0 if the key
     * block has not yet been constructed.
     */
    public int getKeyBlockLength() {
        return keyBlockLength;
    }

    /**
     * Set the length of the entire key block including the header itself!
     */
    public void setKeyBlockLength(int length) {
        keyBlockLength = length;

        if (keyBlockLength > 9999) {
            throw new IllegalArgumentException("Max key block length is 9999");
        }
    }

    /**
     * Recomputes the key block length from the confidential data length. The length is a derived
     * value, so it is always recalculated and never left at a previously generated value. This
     * matters when a key block is regenerated after the clear key or its padding has changed,
     * otherwise the block would declare the length of the previous key.
     */
    public void updateKeyBlockLength(int confidentialDataLength) {
        // Fixed header length + optional blocks length + confidential data ASCII hex length + MAC ASCII hex length
        setKeyBlockLength(
                16
                + buildOptBlocksString().length()
                + confidentialDataLength * 2
                + getKeyBlockType().getMACLen() * 2);
    }

    private void setOptionalBlockList(List<OptionalBlock> list) {
        optionalBlockList = list;
        numOptionalBlocks = optionalBlockList.size();
        if (numOptionalBlocks > 99) {
            throw new UnsupportedOperationException("Too many optional blocks");
        }
    }

    /**
     * Every Optional Block starts with a 2 character identifier followed by a 2 character length
     * field, see {@link OptionalBlock#toString()}.
     */
    private static final int OPTIONAL_BLOCK_OVERHEAD = 4;

    /**
     * Adds the provided optional blocks and append a padding block as needed to ensure the header
     * is a multiple of the encryption block size.
     */
    public void addOptionalBlocksAndPad(OptionalBlock... obs) {
        if (!optionalBlockList.isEmpty()) {
            throw new UnsupportedOperationException("Overwriting existing optional blocks not supported");
        }

        Collections.addAll(optionalBlockList, obs);

        int totalLen = 0;
        for (OptionalBlock ob : obs) {
            totalLen += ob.toString().length();
        }

        final int cipherBlockSize = keyBlockType.getCipherBlockSize();
        if (totalLen % cipherBlockSize != 0) {
            // ASC X9 TR 31-2018 A.5.6: the padding block is formed so that its total length, when
            // added to the combined total length of all other optional blocks, is a multiple of the
            // encryption block size. That total length is the 2 character ID plus the 2 character
            // length field plus the padding data, so only the remainder is available for data.
            //
            // The trailing modulo matters: when totalLen plus the padding block's own overhead is
            // already a multiple of the block size the answer is no padding data at all, not a
            // whole extra block. KC (12) plus KP (16) in a type D block is the case in point,
            // 28 + 4 = 32 is already two 16 byte blocks, so PB carries nothing and the block stays
            // 16 characters shorter than emitting a full block of padding would make it.
            int totalPadLen = (cipherBlockSize - ((totalLen + OPTIONAL_BLOCK_OVERHEAD) % cipherBlockSize))
                    % cipherBlockSize;

            // Random padding is not necessary because the data is not confidential, ASCII '0' is
            // used in examples and is acceptable even in production
            char[] padData = new char[totalPadLen];
            Arrays.fill(padData, '0');
            OptionalBlock padBlock = new OptionalBlock(DefinedOptionalBlockType._PB, new String(padData));
            optionalBlockList.add(padBlock);
        }

        setOptionalBlockList(optionalBlockList);
    }

}
