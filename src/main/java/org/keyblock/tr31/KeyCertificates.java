package org.keyblock.tr31;

import java.io.ByteArrayInputStream;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * The public key certificate carried in the CT optional block of a key block that wraps an
 * asymmetric key, see ANSI X9.143:2021 A.5.7.
 * <p>
 * The block data is a two character certificate format indicator followed by the base64 encoded
 * DER certificate. {@code 00} denotes an X.509 certificate, {@code 01} an EMV certificate and
 * {@code 02} a certificate chain.
 */
public final class KeyCertificates {

    /** Certificate format indicator for an X.509 certificate. */
    public static final String FORMAT_X509 = "00";
    /** Certificate format indicator for an EMV certificate. */
    public static final String FORMAT_EMV = "01";
    /** Certificate format indicator for a certificate chain. */
    public static final String FORMAT_CERTIFICATE_CHAIN = "02";

    private KeyCertificates() { }

    /**
     * The CT optional block of a key block header, or null when there is none.
     */
    public static OptionalBlock certificateBlock(Header header) {
        return header == null ? null : header.getOptionalBlock(DefinedOptionalBlockType._CT.getId());
    }

    /**
     * The certificate format indicator of a CT optional block, the first two characters of its
     * data.
     */
    public static String certificateFormat(OptionalBlock ct) {
        String data = ct.getData();
        if (data.length() < 2) {
            throw new IllegalArgumentException("The CT optional block is too short to hold a format indicator");
        }
        return data.substring(0, 2);
    }

    /**
     * Decode the DER bytes of an X.509 certificate held in a CT optional block.
     *
     * @throws IllegalArgumentException
     *             if the block does not hold a single X.509 certificate
     */
    public static byte[] derBytes(OptionalBlock ct) {
        String format = certificateFormat(ct);
        if (FORMAT_CERTIFICATE_CHAIN.equals(format)) {
            throw new IllegalArgumentException(
                    "The CT optional block holds a certificate chain, decode the individual certificates first");
        }

        return Base64.getDecoder()
                     .decode(ct.getData()
                             .substring(2));
    }

    /**
     * Parse the X.509 certificate held in a CT optional block.
     */
    public static X509Certificate parse(OptionalBlock ct) throws CertificateException {
        if (!FORMAT_X509.equals(certificateFormat(ct))) {
            throw new IllegalArgumentException(
                    "Only X.509 certificates are supported, the CT block format indicator is " + certificateFormat(ct));
        }
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                                                   .generateCertificate(new ByteArrayInputStream(derBytes(ct)));
    }

    /**
     * The certificates of a certificate chain CT optional block, leaf first.
     * <p>
     * The chain form is the {@code 02} format indicator followed by, for each certificate, a two
     * character format indicator, a four character length and that many characters of base64.
     *
     * @throws IllegalArgumentException
     *             if the block is not a certificate chain or is truncated
     */
    public static java.util.List<X509Certificate> parseCertificateChain(OptionalBlock ct) throws CertificateException {
        if (!FORMAT_CERTIFICATE_CHAIN.equals(certificateFormat(ct))) {
            throw new IllegalArgumentException("The CT optional block format indicator is "
                    + certificateFormat(ct) + ", not a certificate chain");
        }

        String data = ct.getData();
        java.util.List<X509Certificate> certificates = new java.util.ArrayList<>();
        int pos = 2;
        while (pos < data.length()) {
            if (pos + 6 > data.length()) {
                throw new IllegalArgumentException("The CT certificate chain is truncated");
            }
            // the length is hex-ASCII, like every other length in a key block header. A CT block is
            // base64, whose alphabet includes characters that are not hex digits, so a corrupted
            // length field has to be reported as such rather than surfacing as a bare
            // NumberFormatException with no indication of which part of the chain is at fault.
            int base64Length = readHexField(data.substring(pos + 2, pos + 6),
                    "CT certificate chain entry at position " + pos);
            int start = pos + 6;
            int end = start + base64Length;
            if (end > data.length() || base64Length <= 0) {
                throw new IllegalArgumentException("The CT certificate chain is truncated");
            }
            byte[] der = Base64.getDecoder()
                               .decode(data.substring(start, end));
            certificates.add((X509Certificate) CertificateFactory.getInstance("X.509")
                                                              .generateCertificate(new ByteArrayInputStream(der)));
            pos = end;
        }
        return certificates;
    }

    /**
     * A length field that is hex ASCII. NumberFormatException is an IllegalArgumentException so
     * this does not widen what callers already catch, it only replaces an unhelpful message with
     * one that names the field.
     */
    private static int readHexField(String field, String what) {
        try {
            return Integer.parseInt(field, 16);
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "The length of the " + what + " is '" + field + "', which is not a hexadecimal number");
        }
    }

    /**
     * The public key of the certificate, which is the key the wrapped private key belongs to.
     */
    public static PublicKey publicKey(OptionalBlock ct) throws CertificateException {
        return parse(ct).getPublicKey();
    }

    /**
     * Check that a wrapped private key is the private half of the public key in a certificate.
     *
     * @see CertificateMatching#matches(Algorithm, byte[], X509Certificate)
     */
    public static boolean matchesCertificate(Algorithm algorithm, byte[] derPrivateKey,
            X509Certificate certificate) {
        return CertificateMatching.matches(algorithm, derPrivateKey, certificate);
    }

    /**
     * Convenience, the wrapped key of a decrypted key block as raw bytes.
     * <p>
     * There is deliberately no hexadecimal counterpart of this in the public API. The unwrapped key
     * is raw key material, and a one line "turn this into something you can log" helper in a
     * library like this is how keys end up in log files. Format it at the call site where you know
     * whether it is going near a log, or use {@link TR31KeyBlock#toDebugString()} which is the
     * already opt-in debug dump of every intermediate value.
     */
    public static byte[] clearKeyBytes(TR31KeyBlock keyBlock) {
        return keyBlock.getClearKey()
                       .array();
    }
}