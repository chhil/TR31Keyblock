package org.keyblock.tr31;

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;

/**
 * Checks that a wrapped asymmetric private key is the private half of the public key in a
 * certificate carried by the CT optional block of the key block.
 * <p>
 * The confidential data of an asymmetric key block is an ASN.1 DER encoding of the private key.
 * Both the bare algorithm specific encodings and PKCS#8 are accepted:
 * <ul>
 * <li>a PKCS#1 {@code RSAPrivateKey} carries the modulus as its second field</li>
 * <li>a SEC1 {@code ECPrivateKey} may carry the public key in the optional {@code [1]} field, which
 * every implementation that writes a key block with a certificate supplies</li>
 * <li>a PKCS#8 {@code PrivateKeyInfo} wraps either of the above and is unwrapped first</li>
 * </ul>
 * None of these carry the public key without the sender having put it there, so no elliptic curve
 * arithmetic is needed: the RSA modulus, or the EC public point, is read out and compared with the
 * certificate. An EC point that cannot be read is an error rather than a mismatch, because a
 * certificate and a key that this class cannot compare have not been shown to belong together.
 * <p>
 * Only the uncompressed X9.62 point encoding (0x04 followed by X and Y) is decoded, and the width
 * of X and Y is taken from the certificate's own domain parameters, so every curve the JCE supports
 * is handled. Compressed (0x02, 0x03) and hybrid (0x06, 0x07) points are rejected with an explicit
 * message rather than reported as a missing public key.
 */
public final class CertificateMatching {

    private CertificateMatching() { }

    /**
     * @param algorithm
     *            the algorithm of the wrapped key
     * @param derPrivateKey
     *            the DER bytes recovered from the key block
     * @param certificate
     *            the certificate to check against
     * @return true when the private key is the private half of the certificate public key
     */
    public static boolean matches(Algorithm algorithm, byte[] derPrivateKey, X509Certificate certificate) {
        switch (algorithm) {
            case _R_RSA: {
                return matchesRsa(derPrivateKey, certificate);
            }
            case _E_ELLIPTIC_CURVE: {
                return matchesEc(derPrivateKey, certificate);
            }
            default: {
                throw new IllegalArgumentException(
                        "Cannot match a certificate against algorithm " + algorithm);
            }
        }
    }

    private static boolean matchesRsa(byte[] der, X509Certificate certificate) {
        if (!(certificate.getPublicKey() instanceof RSAPublicKey)) {
            throw new IllegalArgumentException(
                    "The certificate holds a " + certificate.getPublicKey()
                                                         .getAlgorithm() + " key, not RSA");
        }
        BigInteger modulus = rsaModulus(der);
        if (modulus == null) {
            throw new IllegalArgumentException(
                    "Could not find an RSA modulus in the wrapped key, it is neither PKCS#1 nor PKCS#8");
        }
        return ((RSAPublicKey) certificate.getPublicKey()).getModulus()
                                                         .equals(modulus);
    }

    /**
     * The modulus of a PKCS#1 RSAPrivateKey, which is the INTEGER following the version INTEGER,
     * or null when the wrapped key carries no modulus.
     */
    private static BigInteger rsaModulus(byte[] der) {
        Tlv sequence = Tlv.read(unwrapPkcs8(der), 0);
        if (sequence == null || sequence.tag() != DerTag.SEQUENCE) {
            return null;
        }
        Tlv version = Tlv.read(sequence.value(), 0);
        if (version == null || version.tag() != DerTag.INTEGER) {
            return null;
        }
        Tlv modulus = Tlv.read(sequence.value(), version.totalLength());
        if (modulus == null || modulus.tag() != DerTag.INTEGER) {
            return null;
        }
        return new BigInteger(1, modulus.value());
    }

    /**
     * The inner key of a PKCS#8 {@code PrivateKeyInfo}, or the argument unchanged when it is not
     * one.
     * <p>
     * A PKCS#8 private key is {@code SEQUENCE { INTEGER version, SEQUENCE algorithm,
     * OCTET STRING privateKey }}. Neither of the bare encodings this class also accepts can be
     * mistaken for it, because their second field is an {@code INTEGER} (PKCS#1) or an
     * {@code OCTET STRING} (SEC1) rather than an {@code AlgorithmIdentifier} SEQUENCE.
     */
    private static byte[] unwrapPkcs8(byte[] der) {
        Tlv sequence = Tlv.read(der, 0);
        if (sequence == null || sequence.tag() != DerTag.SEQUENCE) {
            return der;
        }
        byte[] body = sequence.value();
        Tlv version = Tlv.read(body, 0);
        if (version == null || version.tag() != DerTag.INTEGER) {
            return der;
        }
        Tlv algorithm = Tlv.read(body, version.totalLength());
        if (algorithm == null || algorithm.tag() != DerTag.SEQUENCE) {
            return der;
        }
        Tlv privateKey = Tlv.read(body, version.totalLength() + algorithm.totalLength());
        if (privateKey == null || privateKey.tag() != DerTag.OCTET_STRING) {
            return der;
        }
        return privateKey.value();
    }

    private static boolean matchesEc(byte[] der, X509Certificate certificate) {
        if (!(certificate.getPublicKey() instanceof ECPublicKey)) {
            throw new IllegalArgumentException(
                    "The certificate holds a " + certificate.getPublicKey()
                                                         .getAlgorithm() + " key, not EC");
        }

        ECPublicKey certificateKey = (ECPublicKey) certificate.getPublicKey();
        ECPoint found = ecPublicPoint(der, coordinateLength(certificateKey));
        if (found == null) {
            throw new IllegalArgumentException(
                    "Could not read the public key out of the wrapped EC key. A SEC1 ECPrivateKey "
                            + "carrying the optional [1] publicKey field as an uncompressed X9.62 point, "
                            + "or a PKCS#8 key wrapping one, is required. A compressed or hybrid point "
                            + "encoding, or a point on a different curve to the certificate, cannot be matched.");
        }
        return certificateKey.getW()
                             .equals(found);
    }

    /**
     * The width in bytes of one coordinate of a point on the certificate's curve, rounded up.
     */
    private static int coordinateLength(ECPublicKey key) {
        ECParameterSpec parameters = key.getParams();
        if (parameters == null) {
            throw new IllegalArgumentException(
                    "The certificate's EC public key carries no domain parameters, its curve is unknown");
        }
        return (parameters.getCurve()
                          .getField()
                          .getFieldSize() + 7) / 8;
    }

    /**
     * The public point from the optional {@code [1] publicKey} field of a SEC1 ECPrivateKey, which
     * holds an uncompressed point, or null when the field is absent or cannot be decoded.
     *
     * @param coordinateLength
     *            the width in bytes of one coordinate of the expected point
     */
    private static ECPoint ecPublicPoint(byte[] der, int coordinateLength) {
        Tlv sequence = Tlv.read(unwrapPkcs8(der), 0);
        if (sequence == null || sequence.tag() != DerTag.SEQUENCE) {
            return null;
        }

        byte[] body = sequence.value();
        int offset = 0;
        // Walk the fields: the version INTEGER, the privateKey OCTET STRING and the optional
        // [0] parameters and [1] publicKey. Walking until the public key field is found rather
        // than for a fixed number of fields, because the optional ones may be present in any
        // combination.
        while (offset < body.length) {
            Tlv next = Tlv.read(body, offset);
            if (next == null) {
                return null;
            }
            if (next.tag() == DerTag.CONTEXT_1) {
                // [1] EXPLICIT, its content is a BIT STRING holding the encoded point
                Tlv bitString = Tlv.read(next.value(), 0);
                if (bitString == null || bitString.tag() != DerTag.BIT_STRING) {
                    return null;
                }
                return decodePoint(bitString.value(), coordinateLength);
            }
            offset += next.totalLength();
        }
        return null;
    }

    /**
     * An uncompressed EC point, 0x04 followed by X and Y, as used by SEC1 and X9.62. The width of X
     * and Y is fixed by the curve, so anything of a different length, including a compressed or
     * hybrid point, does not decode.
     */
    private static ECPoint decodePoint(byte[] encoded, int coordinateLength) {
        // Skip the unused-bits count that opens a BIT STRING
        if (encoded.length < 1 || encoded[0] != 0) {
            return null;
        }
        byte[] point = Arrays.copyOfRange(encoded, 1, encoded.length);

        if (point.length != 1 + 2 * coordinateLength || point[0] != 0x04) {
            return null;
        }
        // new BigInteger(1, ...) keeps a coordinate whose leading byte is zero, which it would
        // otherwise read as a shorter number
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(point, 1, 1 + coordinateLength));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(point, 1 + coordinateLength, point.length));
        return new ECPoint(x, y);
    }

    static final class DerTag {
        static final int INTEGER = 0x02;
        static final int OCTET_STRING = 0x04;
        static final int BIT_STRING = 0x03;
        static final int SEQUENCE = 0x30;
        static final int CONTEXT_0 = 0xA0;
        static final int CONTEXT_1 = 0xA1;

        private DerTag() { }
    }

    /**
     * One DER tag length value.
     */
    record Tlv(int tag, byte[] value, int totalLength) {

        static Tlv read(byte[] buffer, int offset) {
            if (offset + 2 > buffer.length) {
                return null;
            }
            int tag = buffer[offset] & 0xFF;

            int lengthByte = buffer[offset + 1] & 0xFF;
            int headerLength;
            int valueLength;
            if ((lengthByte & 0x80) == 0) {
                headerLength = 2;
                valueLength = lengthByte;
            } else {
                int lengthBytes = lengthByte & 0x7F;
                if (lengthBytes == 0 || lengthBytes > 2 || offset + 2 + lengthBytes > buffer.length) {
                    return null;
                }
                valueLength = 0;
                for (int i = 0; i < lengthBytes; i++) {
                    valueLength = (valueLength << 8) | (buffer[offset + 2 + i] & 0xFF);
                }
                headerLength = 2 + lengthBytes;
            }

            if (offset + headerLength + valueLength > buffer.length) {
                return null;
            }

            byte[] value = new byte[valueLength];
            System.arraycopy(buffer, offset + headerLength, value, 0, valueLength);
            return new Tlv(tag, value, headerLength + valueLength);
        }
    }
}