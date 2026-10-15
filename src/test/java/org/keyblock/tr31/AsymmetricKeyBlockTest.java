package org.keyblock.tr31;

import static org.junit.jupiter.api.Assertions.*;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import at.favre.lib.bytes.Bytes;

/** Asymmetric key blocks, examples from ANSI X9.143:2021 sections 8.5 and 8.6. */
class AsymmetricKeyBlockTest {

    /** ANSI X9.143:2021 8.5, R_RSA private key with a CT optional block. */
    private static final String KBPK_17 = "FA36E44278DB3AB5F298F9F7DA8F1F88";
    private static final String BLOCK_17 = "D3776S0RS00N0400CT0004050000MIIDszCCApugAwIBAgIIKpD5FKMfCZEwDQYJKoZIhvcNAQELBQAwLTEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxEjAQBgNVBAMMCVNhbXBsZSBDQTAeFw0yMDA4MTUwMjE0MTBaFw0yMTA4MTUwMjE0MTBaME8xFzAVBgNVBAoMDkFscGhhIE1lcmNoYW50MR8wHQYDVQQLDBZUTFMgQ2xpZW50IENlcnRpZmljYXRlMRMwEQYDVQQDDAoxMjM0NTY3ODkwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1sRg+wEuje3y14V0tFHpvxxpY/fyrldB0nRctBDn4AvkBfyJuDLG59vqkGXVd8J8YQdwEHZJrVq+7B8rjtM6PMoyH/7QAZZAC7tw740P4cfen1IryubZVviV9QUp+gHToelZfr1rfIsuEGhzo6UhwY70kkS87/rYHCVathZEjMmvUIEdpzg0PZ2+Heg6D35OQ70I+np+BsEQf71Zr+d2iKqVGEd50l8tbn4W3A4rOyUERPTaACwS9rvdF7nlmTqSI5ybN6lmm37a71h77n6M54aaw2KkJYWVo+1stUTyFVsv/YBs9aylbBHQOYqp/U2tB0TxM58QYGzyaWvNqbFzOQIDAQABo4G0MIGxMAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBR837QRAGx5uL9xDnRjr9L9WSBSlzAfBgNVHSMEGDAWgBSlXhVYy9bic9OLnRsxsFgKQQbLmTA/BgNVHR8EODA2MDSgMqAwhi5odHRwOi8vY3JsLmFscGhhLW1lcmNoYW50LmV4YW1wbGUvU2FtcGxlQ0EuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQCH6JusIBSkRDqzAohaSoJVAEwQGMdcUSQWDfMyJjZqkOep1kT8Sl7LolFmmmVRJdkTWZe4PxBfQUc/eIql9BIx90506B+j9aoVA7212OExAid78GgqKA6JoalhYQKRta9ixY8iolydTYyEYpegA1jFZavMQma4ZGwX/bDJWr4+cJYxJXWaf67g4AMqHaWC8J60MVjrrBe9BZ0ZstuIlNkktQUOZanqxqsrFeqz02ibwTwNHtaHQCztB4KgdTkrTNahkqeq6xjafDoTllNo1EddajnbA/cVzF9ZCNigDtg5chXHWIQbgEK7HmU3sY3/wd2Bh1KdF3+vpN+5iZMRNv7ZKP1001D77F007724TS1320200818221218ZPB0D000000000A7C9F8FA80A4BA3555CA071503CE1A6133649BB18A5A9130492172CA4E7360C060379738A28503230BDB04EED4E9B209643867613F5090A0E0392C21EB74747795B397315AB5D1F49A33693533E73AC0BEDA172FF530BE986F5EC1C25F481F05A69DF8B33624E621AF35FFAEC06C2005F37872923EEBFF38182FB290BFBA2A9FF88AD36278625868FA38A0DC9A53E0202C4D1DEF3B9DACFD249DA85DE3CCF92A8E6C0F8CDF8DE5FD17331BE5D580F210CE4EA1B01F1A0BFD6EFF410A71661234AD363D4B60885F00358729900FF95D7C87D3DE6FB4C83B24C8C7BB5A2E3763E9CBA50A0E3A8C1AF908699952BCB6B038FEA9D13FDE08801DC0573E55B842219DBF6D5DA5F028C73793AA718D01DE93D85AE06E7E08DC94ADB4EAA51B6DDAEA3750D0B77467D2982AC96F3EB28889715CBB81C71E97A60E58D44977C1D8220A422E98E17ACEBF72A8A18D4E7FC1695F442860E6063E8BB6BFF2184F77E635C2F5A02DADE4897A3B1374145C3AD6DF06C0D556F5DE9454CF40C4FC8922DFE245F868E668F1DA5BE0079F9D1D1861CA4B5E6C782F296098C07CB43784D64D8B8557410E5BAFF59333A791FF030EB0661C0590A665B50A3A727217100C4550B2AD9C96C658D6731C09B55DFAE665952E2913A4E090F45DCEB45D6683C3FC15E3A4CA49C7F2E684B3580DB47A53E5BDB228FAD250C584548D5DEDBB45004B5E0E75C37ACE8167CC6D9574A74876718D2F42996622B8EC0B895FF7A6739E4CF64B7F03FABDFBC0A565CB3455736D2B4E2B64D6EC175A569F78DB7ACB331B00804279677F4BFD0C35CBF0A38D646AA9051961123E16075A06B6331A9A30601AF3FD6A89AD9924AE1D9EC2FE0FF3B3A1B3E3E13D09B08B80D91F9EDF51B2E6D8DABD0FEB6C5C1085A11FA6A98CE8CC09E36C8A24D981A74E140EF30912E8CDBBE2A0CBD52B40C72D1958F4BB2F49BCBABBD80116FEF21BC91D219EEAEDA4DC11692C624B0836C3137A3BEE4549DEAB750A9DD5ACA7E3F822084783CDFEEB765EBEB9E3CFF053E8B8D5A1F1854B8AFF6325F10B81C7627D0DA895B1D19FEEF0AE3F3E138E87C4ADDF0BA53CA40ED0D1452044600FF4838D710F6D03474C317AC306DD7DA169B6C918E999E3A50DA1A34DDFCA3899F4469B9E969C0BD144F04B2621AB9E9E18455D526844155309565DA9D1726CD3A7ACC5FEDEF30DED078547CED31CEF84A31A810FA966F303CB950ACC324AE54BFAB9A04FAD93C38CD6239D7FAD2C59A9B71171F5676DA8ED3A3FFB5287DF141C1F5CE972CA26857AD3039B82B625960A7859F19EF0E94F8C4680A33189870942139DDFA64D5095FA46EB49085DB99EFC9C6A3F3A290DB9592F8B76B017113F7D1FEFE52E70FE26574467257CFEEA6D3F2BBD1BAEDDDCE3468827568A78536DE78E7AC872247BDB120A55DDE16A3D0CFBB7D097AD7AD0FA2671390D8D532A3915F5B3163FF1EE23553D83A1109980859C420F754BC74ECD1449B9A60EA252D3F035D715BCBD491485261C51238926E290BD7F0617E90BD6AB8B46443B05C28D61F8BB897417926623AF91B499C661629795165EF56460850F1D4F9CE199C2B9E21F1884A4D14644DAE5FB963B880EC2FFF70021772D524289D068A24F0283C42F0B4779996D2CF60EE6E45C364E2547DB92361B3DBCEDBAA96B9F10A1AAA1AB23CDE1B75F3299D4544787A07F6A9F7127";
    private static final String KEY_17 = "308204A40201000282010100D6C460FB012E8DEDF2D78574B451E9BF1C6963F7F2AE5741D2745CB410E7E00BE405FC89B832C6E7DBEA9065D577C27C610770107649AD5ABEEC1F2B8ED33A3CCA321FFED00196400BBB70EF8D0FE1C7DE9F522BCAE6D956F895F50529FA01D3A1E9597EBD6B7C8B2E106873A3A521C18EF49244BCEFFAD81C255AB616448CC9AF50811DA738343D9DBE1DE83A0F7E4E43BD08FA7A7E06C1107FBD59AFE77688AA95184779D25F2D6E7E16DC0E2B3B250444F4DA002C12F6BBDD17B9E5993A92239C9B37A9669B7EDAEF587BEE7E8CE7869AC362A4258595A3ED6CB544F2155B2FFD806CF5ACA56C11D0398AA9FD4DAD0744F1339F10606CF2696BCDA9B17339020301000102820101009A6193ED1ACE624BF7D2A1266130B8BC1E2A4C284214BCB89E15F345A519695E62CD42D9A4C52B62241D9B2AF8A61BF1D8B5C602AF650AEE3E6BF184182912A5FC1AC8111D68E69EA75058407AC03DE6B4CB060060DC4CC34DF24DAD269D868EA0C6E3044E1963EF906F4F06414E44D3A4757E67570192E9A261DFB12094AA36476582272EDAB0F56F816D9FA69580B3AB053237135BD1DDDB42AF77E11E1629F5A11B22C5E3E2DB3E8767A90B94414898DCCBB47EFE619F0620AC29C389FB464CE9C5E243963E13B6DA38EFAE1330AEFB54C0D5E2E59B6D7FBE4B3A22EE483F74E74D4A4A25978C65F4AC5829C34260930C85ECEA1FB24DB52A438D4EB2CF6102818100ED003DEEB8013AF4E4EBE172FE474B23FE20128805840C2D277E3E308D5B44527F1ED33C07AF350D5B22B27E082CD101DD2DE54DC8DF8F91D4BA5768EB9EC5F27DB5D358EA5E0DEE08A535677CB3F765789C9DAE56B7421B9E54525EF928AB2885BF098E837999AD0CA3CA6AC642EA9AD1331856B0CCEE5DF01FED1B2F63C3A502818100E7FBDA0A71C926DD51F037206D901A297554A39BBC9239794421F1F54D29766E50E016CA5701BDA79AEC543F5066B3730E053EA4B5872D25C29673CA8457B07390D11AF23F2247A1133FC2522B96CB02DA77D927FEE6661066058D1A4D85FE3C1D3418542F24B3982B4DDFB4192E512EDA1BAAAA59955B50945DD083E26E4D0502818002D4E0E88C3C3F87138119F574C2474C8BC9B84EF5B9E92754F4762BC05499D15E8170C6A3D4DD0E66CB5854972669ECDAC6A499B44FAF786F91366023888716E9979589D76AFE419CCAD4838302E76EC7ED1F1929221161211822CFCDAC45B73B39D81462CFBE1D4A2C5ECBBDC8A8E2E6A2F4A47C82464ACB06A69F8F86629D0281804E98A99AF84A2A7CB992255B3B43A3598083189B5F1C3B94B65CB9D95E373A04CE29DE0ED7C3A339F1E737F3EB8DA026CF0D3FD81618A25734C23CA0D48DD11E9666023728E4B857FE698FB0BF4BEBA41FD8931E55E2419A34B694C3E0981136D4BE1DB007F8EB5016FBDF5AE95D23EC37C13FE54F4CA70F79F4FEFC6FEEE6F1028181008321C2F1E8914C0AE09C418ACFEBB8A7B86A1E7144182F5145FBA90AF104DE3BC7604D86A831AC2F38DA356C99BC60BEA80E26EC8B7FAF8BB84A8661EF564BDC65DA0519F5E3CE81FF491CC71DA0813960048B225E61C56684D3CE01AE28A212C9ACCE946E2AAB80ADD51B00093029C5D52E9AF6C8A3EB861641B00E23636A68";
    /** ANSI X9.143:2021 8.6, E_ELLIPTIC_CURVE private key with a CT optional block. */
    private static final String KBPK_18 = "88E1AB2A2E3DD38C1FA039A536500CC8A87AB9D62DC92C01058FA79F44657DE6";
    private static final String BLOCK_18 = "D1840S0ES00N0400CT000405CC020002F0MIICLjCCAdSgAwIBAgIIGDrdWBxuNpAwCgYIKoZIzj0EAwIwMTEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxFjAUBgNVBAMMDVNhbXBsZSBFQ0MgQ0EwHhcNMjAwODE1MDIxMDEwWhcNMjEwODE1MDIxMDEwWjBPMRcwFQYDVQQKDA5BbHBoYSBNZXJjaGFudDEfMB0GA1UECwwWVExTIENsaWVudCBDZXJ0aWZpY2F0ZTETMBEGA1UEAwwKMTIzNDU2Nzg5MDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEI/SLrH6fITA9y6Y3BneuoT/5+EHSepZxCYeSstGll2sVvmSDZWWSbN6lh5Fb/zagrDjjQ/gZtWIOTf2wL1vSGjgbcwgbQwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFHuvP526vFMywEoVoXZ5aXNfhnfeMB8GA1UdIwQYMBaAFI+ZFhOWF+oMtcfYwg15vH5WmWccMEIGA1UdHwQ7MDkwN6A1oDOGMWh0dHA6Ly9jcmwuYWxwaGEtbWVyY2hhbnQuZXhhbXBsZS9TYW1wbGVFQ0NDQS5jcmwwCgYIKoZIzj0EAwIDSAAwRQIhAPuWWvCTmOdvQzUjCUmTX7H4sX4Ebpw+CI+aOQLu1DqwAiA0eR4FdMtvXV4P6+WMz5B10oea5xtLTfSgoBDoTkvKYQ==0002C4MIICDjCCAbOgAwIBAgIIfnOsCbsxHjwwCgYIKoZIzj0EAwIwNjEXMBUGA1UECgwOQWxwaGEgTWVyY2hhbnQxGzAZBgNVBAMMElNhbXBsZSBSb290IEVDQyBDQTAeFw0yMDA4MTUwMjEwMDlaFw0zMDA4MTMwMjEwMDlaMDExFzAVBgNVBAoMDkFscGhhIE1lcmNoYW50MRYwFAYDVQQDDA1TYW1wbGUgRUNDIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHCanM9n+Rji+3EROj+HlogmXMU1Fk1td7N3I/8rfFnre1GwWCUqXSePHxwQ9DRHCV3oht3OUU2kDfitfUIujA6OBrzCBrDASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUj5kWE5YX6gy1x9jCDXm8flaZZxwwHwYDVR0jBBgwFoAUvElIifFlt6oeUaopV9Y0lJtyPVQwRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NybC5hbHBoYS1tZXJjaGFudC5leGFtcGxlL1NhbXBsZVJvb3RFQ0NDQS5jcmwwCgYIKoZIzj0EAwIDSQAwRgIhALT8+DG+++KuqqUGyBQ4YG4s34fqbujclxZTHxYWVVSNAiEAn3v5Xmct7fkLpkjGexiHsy6D90r0K2LlUqpN/069y5s=KP10012331550BC9TS1320200818004100ZPB11000000000000023806274FDDE312047FA37117320D914DD1CF20705A140E39FF88DF107110F26DDFDB20AD909B4C67987C76907C6518B63C8BB7969A52BA3EE6218C9B29F02C243D23E5DF5F87D4CBC0E587DD619F1F228D3F605316DC39DDD6E9D13BAB633D13A97BE7EF67DBEECADA32FA968E57BDF87EE5AEAA47CDCF427154AE66508B99EF6186011C7BE905F875B24C5D05EA14E";
    private static final String KEY_18 = "307702010104202D493257A45B34C11B6526A03DB4D8AE16EE87A0C16BDF1BE23C2DD8B164A2D3A00A06082A8648CE3D030107A14403420004423F48BAC7E9F21303DCBA6370677AEA13FF9F841D27A9671098792B2D1A5976B15BE64836565926CDEA587915BFF36A0AC38E343F819B5620E4DFDB02F5BD21";

    /**
     * A self signed certificate on secp384r1, base64 DER. Its private half is
     * {@link #P384_KEY_PKCS8}. The point is on a curve whose coordinates are 48 bytes, so it
     * only matches if the point is decoded against the certificate's own parameters rather than
     * against a hard coded P-256 width.
     */
    private static final String P384_CERT =
            "MIIBrzCCATWgAwIBAgIUDlzTyiLHyi1ZDWJ2KWUtftNf6ucwCgYIKoZIzj0EAwIwHzEdMBsGA1UEAwwUVFIzMSBQMzg0" +
            "IHJlZ3Jlc3Npb24wHhcNMjYxMDE1MDMyMDI5WhcNNDYxMDEwMDMyMDI5WjAfMR0wGwYDVQQDDBRUUjMxIFAzODQgcmVn" +
            "cmVzc2lvbjB2MBAGByqGSM49AgEGBSuBBAAiA2IABHNgfXO3nrFTZtjmgC9bro8K9Xf1oW4LKTvgt4BK+2HUSEaS00ib" +
            "PimWNbMhNidNSlFr2MgHoknMESvEzXX/sOyVPvqkjifTq+Qz8A/zVZ2CZFnZLZQhob5YqgkGGZSnhqMyMDAwHQYDVR0O" +
            "BBYEFATtmBiY0g6KepDekjqmVU2W0Tu6MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDaAAwZQIxANPlEbTy2yPl" +
            "9JG5FxqS9oexdHRM6clUzvFr/tf48daMNGGIltdFzVWXyoyagq0FBwIwG4P51i0rs4bFfEZx1knkhii8Ctydr5JK/6Ex" +
            "ge/Hoi5iZ4tJDquxA6U7c+O99OSG";

    /** The PKCS#8 private key of {@link #P384_CERT}, a SEC1 ECPrivateKey on secp384r1. */
    private static final String P384_KEY_PKCS8 =
            "3081B6020100301006072A8648CE3D020106052B8104002204819E30819B0201010430AD7B668A1436624636A51B" +
            "39D3C14B5E1316891877CB6D99A87DCEDE85FF85A13ECB67D10EC856E8DADBBB6260B0CBA3A1640362000473607D" +
            "73B79EB15366D8E6802F5BAE8F0AF577F5A16E0B293BE0B7804AFB61D4484692D3489B3E299635B32136274D4A51" +
            "6BD8C807A249CC112BC4CD75FFB0EC953EFAA48E27D3ABE433F00FF3559D826459D92D9421A1BE58AA09061994A7" +
            "86";

    /** rsaEncryption AlgorithmIdentifier, the PKCS#8 algorithm field of an RSA key. */
    private static final String ALGORITHM_RSA = "300D06092A864886F70D0101010500";

    /** id-ecPublicKey AlgorithmIdentifier, the PKCS#8 algorithm field of an EC key. */
    private static final String ALGORITHM_EC = "301306072A8648CE3D020106082A8648CE3D030107";

    @Test
    @DisplayName("An RSA key block unwraps to the wrapped private key")
    void unwrapRsaKeyBlock() throws Exception {
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(BLOCK_17, KBPK_17);

        assertEquals(Algorithm._R_RSA, kb.getHeader().getAlgorithm());
        assertEquals(Bytes.parseHex(KEY_17), kb.getClearKey());
        // the wrapped key is an ASN.1 DER SEQUENCE
        assertEquals(0x30, kb.getClearKey().byteAt(0) & 0xFF, "DER SEQUENCE tag");
    }

    @Test
    @DisplayName("An EC key block unwraps to the wrapped private key")
    void unwrapEcKeyBlock() throws Exception {
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(BLOCK_18, KBPK_18);

        assertEquals(Algorithm._E_ELLIPTIC_CURVE, kb.getHeader().getAlgorithm());
        assertEquals(Bytes.parseHex(KEY_18), kb.getClearKey());
    }

    @Test
    @DisplayName("The CT optional block parses as an X.509 certificate")
    void parseCertificate() throws Exception {
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(BLOCK_17, KBPK_17);

        OptionalBlock ct = KeyCertificates.certificateBlock(kb.getHeader());
        assertNotNull(ct, "the block carries a CT optional block");
        assertEquals("CT", ct.getId());
        assertEquals(KeyCertificates.FORMAT_X509, KeyCertificates.certificateFormat(ct));

        X509Certificate certificate = KeyCertificates.parse(ct);
        assertEquals("RSA", certificate.getPublicKey().getAlgorithm());
    }

    @Test
    @DisplayName("The certificate matches the wrapped private key")
    void certificateMatchesWrappedKey() throws Exception {
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(BLOCK_17, KBPK_17);

        X509Certificate certificate = KeyCertificates.parse(KeyCertificates.certificateBlock(kb.getHeader()));
        assertTrue(KeyCertificates.matchesCertificate(Algorithm._R_RSA, kb.getClearKey().array(), certificate),
                "the certificate must be the public half of the wrapped key");
    }

    @Test
    @DisplayName("A certificate does not match an unrelated key")
    void unrelatedCertificateDoesNotMatch() throws Exception {
        TR31KeyBlock rsa = new TR31KeyBlock();
        rsa.decryptKeyBlock(BLOCK_17, KBPK_17);
        X509Certificate rsaCert = KeyCertificates.parse(KeyCertificates.certificateBlock(rsa.getHeader()));

        TR31KeyBlock ec = new TR31KeyBlock();
        ec.decryptKeyBlock(BLOCK_18, KBPK_18);

        assertThrows(IllegalArgumentException.class,
                () -> KeyCertificates.matchesCertificate(Algorithm._R_RSA, ec.getClearKey().array(), rsaCert));
    }

    @Test
    @DisplayName("The certificate chain of an EC key block parses and matches the wrapped key")
    void ecCertificateChainMatchesWrappedKey() throws Exception {
        // The X9.143 8.6 example carries a certificate chain rather than a single certificate,
        // and the wrapped key is a SEC1 ECPrivateKey whose public key lives in the optional
        // [1] field after the [0] curve parameters. Both had to work for this to pass.
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(BLOCK_18, KBPK_18);

        OptionalBlock ct = KeyCertificates.certificateBlock(kb.getHeader());
        assertEquals(KeyCertificates.FORMAT_CERTIFICATE_CHAIN, KeyCertificates.certificateFormat(ct));

        java.util.List<X509Certificate> chain = KeyCertificates.parseCertificateChain(ct);
        assertEquals(2, chain.size(), "the chain holds a leaf and an issuer");

        X509Certificate leaf = chain.get(0);
        assertEquals("EC", leaf.getPublicKey()
                                  .getAlgorithm());
        assertTrue(KeyCertificates.matchesCertificate(Algorithm._E_ELLIPTIC_CURVE, kb.getClearKey()
                                                                                                   .array(),
                leaf), "the leaf certificate must be the public half of the wrapped EC key");
    }

    @Test
    @DisplayName("Strict optional block validation still accepts a base64 certificate")
    void strictValidationAcceptsCertificateBlocks() throws Exception {
        // The CT data is base64, which contains '+' and '/' and is not alphanumeric, so this
        // only passes because CT is checked as base64 rather than as a plain character format.
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(BLOCK_17, KBPK_17, true);

        assertEquals(Bytes.parseHex(KEY_17), kb.getClearKey());
    }

    @Test
    @DisplayName("An extended length optional block round trips")
    void extendedLengthOptionalBlockRoundTrips() throws Exception {
        // the CT block in the RSA example uses the extended length form
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(BLOCK_17, KBPK_17);

        Header parsed = new Header(BLOCK_17);
        assertEquals(kb.getHeader().toString(), parsed.toString());
        assertEquals(4, parsed.getOptionalBlocks().size());

        // rebuilding the blocks must reproduce the same header bytes
        StringBuilder rebuilt = new StringBuilder();
        for (OptionalBlock ob : parsed.getOptionalBlocks()) {
            rebuilt.append(ob.toString());
        }
        assertEquals(parsed.toString().substring(16), rebuilt.toString());
    }

    @Test
    @DisplayName("An RSA key wrapped in PKCS#8 matches its certificate, as the bare PKCS#1 key does")
    void pkcs8WrappedRsaKeyMatches() throws Exception {
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(BLOCK_17, KBPK_17);
        X509Certificate certificate = KeyCertificates.parse(KeyCertificates.certificateBlock(kb.getHeader()));

        // The X9.143 example carries a bare PKCS#1 RSAPrivateKey, an HSM hands back PKCS#8
        byte[] pkcs8 = privateKeyInfo(ALGORITHM_RSA, Bytes.parseHex(KEY_17).array());

        assertTrue(KeyCertificates.matchesCertificate(Algorithm._R_RSA, pkcs8, certificate),
                "a PKCS#8 wrapped RSA key must match the same certificate as the PKCS#1 form");
    }

    @Test
    @DisplayName("An EC key wrapped in PKCS#8 matches its certificate, as the bare SEC1 key does")
    void pkcs8WrappedEcKeyMatches() throws Exception {
        X509Certificate leaf = leafOf(BLOCK_18, KBPK_18);

        byte[] pkcs8 = privateKeyInfo(ALGORITHM_EC, Bytes.parseHex(KEY_18).array());

        assertTrue(KeyCertificates.matchesCertificate(Algorithm._E_ELLIPTIC_CURVE, pkcs8, leaf),
                "a PKCS#8 wrapped EC key must match the same certificate as the SEC1 form");
    }

    @Test
    @DisplayName("An EC key on a curve wider than P-256 matches its certificate")
    void largerCurveEcKeyMatches() throws Exception {
        // secp384r1 coordinates are 48 bytes, so a decoder that assumes the 32 byte P-256 width
        // reports that the wrapped key carries no public key at all
        X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                                                                                .generateCertificate(new ByteArrayInputStream(Base64.getDecoder()
                                                                                                                                                                  .decode(P384_CERT)));

        assertTrue(KeyCertificates.matchesCertificate(Algorithm._E_ELLIPTIC_CURVE,
                Bytes.parseHex(P384_KEY_PKCS8).array(), certificate),
                "the width of the point must come from the certificate, not from a fixed P-256 size");
    }

    @Test
    @DisplayName("A point that cannot be decoded is reported as such, not as a missing public key")
    void undecodableEcPointIsReportedClearly() throws Exception {
        X509Certificate p256 = leafOf(BLOCK_18, KBPK_18);

        // the secp384r1 point is 96 bytes where a secp256r1 one is 64, so it does not decode
        // against the P-256 certificate
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> KeyCertificates.matchesCertificate(Algorithm._E_ELLIPTIC_CURVE,
                        Bytes.parseHex(P384_KEY_PKCS8).array(), p256));

        assertTrue(e.getMessage()
                       .contains("Could not read the public key"), e.getMessage());
        assertFalse(e.getMessage()
                    .contains("does not carry its public key"),
                "a point of the wrong width is not a key that lacks a public key");
    }

    @Test
    @DisplayName("A corrupted certificate chain is reported as such, not as a bare parse failure")
    void corruptedCertificateChainIsReportedClearly() {
        // A CT block is base64, so G to Z are legal there but not hex digits. A chain entry whose
        // length field holds one has to name the field rather than surfacing as an unhelpful
        // NumberFormatException.
        OptionalBlock ct = new OptionalBlock(DefinedOptionalBlockType._CT, "02" + "00ZZZZ" + "QUJD");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> KeyCertificates.parseCertificateChain(ct));
        assertTrue(e.getMessage()
                       .contains("not a hexadecimal number"), e.getMessage());
        assertTrue(e.getMessage()
                       .contains("position 2"), "the message should say which entry is at fault: "
                               + e.getMessage());
    }

    @Test
    @DisplayName("A truncated certificate chain is reported as truncation")
    void truncatedCertificateChainIsReportedClearly() {
        // chain indicator, then one entry: certificate format 00, a length of 10, but only 4
        // characters of base64 follow
        OptionalBlock ct = new OptionalBlock(DefinedOptionalBlockType._CT, "02" + "00" + "000A" + "QUJD");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> KeyCertificates.parseCertificateChain(ct));
        assertTrue(e.getMessage()
                       .contains("truncated"), e.getMessage());
    }

    private static X509Certificate leafOf(String keyBlock, String kbpkHex) throws Exception {
        TR31KeyBlock kb = new TR31KeyBlock();
        kb.decryptKeyBlock(keyBlock, kbpkHex);
        return KeyCertificates.parseCertificateChain(KeyCertificates.certificateBlock(kb.getHeader()))
                                                                                          .get(0);
    }

    /** SEQUENCE { INTEGER 0, algorithm, OCTET STRING key }, a PKCS#8 PrivateKeyInfo. */
    private static byte[] privateKeyInfo(String algorithmHex, byte[] key) {
        return der(0x30, concat(der(0x02, new byte[] { 0 }), der(0x30, Bytes.parseHex(algorithmHex).array()),
                der(0x04, key)));
    }

    private static byte[] der(int tag, byte[] value) {
        byte[] encodedLength = derLength(value.length);
        byte[] out = new byte[1 + encodedLength.length + value.length];
        out[0] = (byte) tag;
        System.arraycopy(encodedLength, 0, out, 1, encodedLength.length);
        System.arraycopy(value, 0, out, 1 + encodedLength.length, value.length);
        return out;
    }

    private static byte[] derLength(int length) {
        if (length < 0x80) {
            return new byte[] { (byte) length };
        }
        if (length <= 0xFF) {
            return new byte[] { (byte) 0x81, (byte) length };
        }
        return new byte[] { (byte) 0x82, (byte) (length >> 8), (byte) length };
    }

    private static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] out = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }
}
