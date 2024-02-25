package org.keyblock.tr31;

import org.keyblock.utils.Util;

import at.favre.lib.bytes.Bytes;

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
        keyBlockType = KeyblockType.fromString(header.substring(0, 1)).get();
        keyBlockLength = Integer.parseInt(header.substring(1, 5));
        keyUsage = KeyUsage.fromString(header.substring(5, 7)).get();
        algorithm = Algorithm.fromString(header.substring(7, 8)).get();
        keyUseFor = KeyUseFor.fromString(header.substring(8, 9)).get();
        version = header.substring(9, 11);
        export = Export.fromString(header.substring(11, 12)).get();
        numOptionalBlocks = Integer.parseInt(header.substring(12, 14));
        reserved = header.substring(14, 16);

        int pos = 16;

        for (int i = 0; i < numOptionalBlocks; i++) {
            String obId = header.substring(pos, pos += 2);

            int obDataLen;
            int obLen = Integer.parseInt(header.substring(pos, pos += 2), 16);
            if (obLen == 0) {
                int obLenOfLen = Integer.parseInt(header.substring(pos, pos += 2), 16);
                if (obLenOfLen == 0) {
                    throw new IllegalArgumentException();
                }

                obLen = Integer.parseInt(header.substring(pos, pos += obLenOfLen), 16);
                obDataLen = obLen - 2 - 2 - obLenOfLen;
            } else {
                obDataLen = obLen - 2 - 2;
            }

            String obData = header.substring(pos, pos += obDataLen);
            optionalBlockList.add(new OptionalBlock(obId, obData));
        }

        setOptionalBlockList(optionalBlockList);
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
            .append(reserved);

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
     * Set the length of the entire key block including the header itself!
     */
    public void setKeyBlockLength(int length) {
        keyBlockLength = length;

        if (keyBlockLength > 9999) {
            throw new IllegalArgumentException("Max key block length is 9999");
        }
    }

    /**
     * Updates the key block length using the given confidential data length. This operation is
     * ignored if the key block length has already been set.
     */
    public void updateKeyBlockLength(int confidentialDataLength) {
        if (keyBlockLength == 0) {
            // Fixed header length + optional blocks length + confidential data ASCII hex length + MAC ASCII hex length
            setKeyBlockLength(
                    16
                    + numOptionalBlocks
                    + confidentialDataLength * 2
                    + getKeyBlockType().getMACLen() * 2);
        }
    }

    private void setOptionalBlockList(List<OptionalBlock> list) {
        optionalBlockList = list;
        numOptionalBlocks = optionalBlockList.size();
        if (numOptionalBlocks > 99) {
            throw new UnsupportedOperationException("Too many optional blocks");
        }
    }

    private static final int MIN_PAD_OPTIONAL_BLOCK_SIZE = 4;

    /**
     * Adds the provided optional blocks and append a padding block as needed to ensure the header
     * is a multiple of the encryption block size.
     */
    public void addOptionalBlocksAndPad(OptionalBlock... obs) {
        if (!optionalBlockList.isEmpty()) {
            throw new UnsupportedOperationException("Overwriting existing optional blocks not supported");
        }

        Collections.addAll(optionalBlockList, obs);

        // Add a padding block if needed
        int totalLen = 0;
        for (OptionalBlock ob : obs) {
            totalLen += ob.toString().length();
        }

        final int cipherBlockSize = keyBlockType.getCipherBlockSize();
        if (totalLen % cipherBlockSize != 0) {
            int totalPadLen = totalLen % cipherBlockSize;

            if (totalPadLen < MIN_PAD_OPTIONAL_BLOCK_SIZE) {
                totalPadLen += cipherBlockSize;
            }

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
