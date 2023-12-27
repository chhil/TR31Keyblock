package org.keyblock.tr31;

import org.keyblock.utils.Util;

public class OptionalBlock {

    private final String id;
    private final String data;

    public OptionalBlock(String id, String data) {
        this.id = id;
        this.data = data;

        if (data.length() > 0xFFFF) {
            throw new IllegalArgumentException("Data too long for optional block");
        }
    }

    public OptionalBlock(DefinedOptionalBlockType type, String data) {
        this(type.getId(), data);
    }

    public String getId() {
        return id;
    }

    public String getData() {
        return data;
    }

    @Override
    public String toString() {
        // this field contains the length of that Optional Block in bytes,
        // including the field's ID, length, and data.

        int blockLength = 2 + 2 + data.length(); // assume simple format first

        String lenEncoded;
        if (blockLength > 0xFF) {
            // cannot use simple format, need to use extended format
            blockLength = 2 + 2 + 4 + data.length();
            lenEncoded = "00" + "04" + Util.padLeft(Integer.toString(blockLength, 16), 4, '0');
        } else {
            lenEncoded = Util.padLeft(Integer.toString(blockLength, 16), 2, '0');
        }

        return id + lenEncoded.toUpperCase() + data;
    }
}
