package org.keyblock.tr31;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

public enum KeyUsage {

                      _B0_BDK_BASE_DERIVATION_KEY("B0", KeyUseFor.X_DERIVE_OTHER_KEYS),
                      _B1_INITIAL_DUKPT_KEY("B1", KeyUseFor.X_DERIVE_OTHER_KEYS),
                      _B2_BASE_KEY_VARIANT_KEY("B2", KeyUseFor.Y_CREATE_KEY_VARIANTS),
                      _C0_CVK_CARD_VERIFICATION_KEY(
                                                    "C0",
                                                    KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                    KeyUseFor.G_MAC_GENERATE_ONLY,
                                                    KeyUseFor.V_MAC_VERIFY_ONLY),
                      _D0_DATA_ENCRYPTION(
                                          "D0",
                                          KeyUseFor.B_BOTH_ENCRYPT_AND_DECRYPT,
                                          KeyUseFor.D_DECRYPT_ONLY,
                                          KeyUseFor.E_ENCRYPT_ONLY),
                      _D1_ASYMMETRIC_DATA_ENCRYPTION(
                                                     "D1",
                                                     KeyUseFor.B_BOTH_ENCRYPT_AND_DECRYPT,
                                                     KeyUseFor.D_DECRYPT_ONLY,
                                                     KeyUseFor.E_ENCRYPT_ONLY),
                      _D2_DATA_ENCRYPTION_KEY_WITH_DECIMALIZATION_TABLE(
                                                                        "D2",
                                                                        KeyUseFor.B_BOTH_ENCRYPT_AND_DECRYPT,
                                                                        KeyUseFor.D_DECRYPT_ONLY,
                                                                        KeyUseFor.E_ENCRYPT_ONLY),
                      _E0_EMV_CHIP_CARD_MASTER_KEY_APPLICATION_CRYPTOGRAMS("E0", KeyUseFor.X_DERIVE_OTHER_KEYS),
                      _E1_EMV_CHIP_CARD_MASTER_KEY_SECURE_MESSAGING_FOR_CONFIDENTIALITY(
                                                                                        "E1",
                                                                                        KeyUseFor.X_DERIVE_OTHER_KEYS),
                      _E2__EMV_CHIP_CARD_MASTER_KEY_SECURE_MESSAGING_FOR_INTEGRITY("E2", KeyUseFor.X_DERIVE_OTHER_KEYS),
                      _E3_EMV_CHIP_CARD_MASTER_KEY_DATA_AUTHENTICATION_CODE("E3", KeyUseFor.X_DERIVE_OTHER_KEYS),
                      _E4_EMV_CHIP_CARD_MASTER_KEY_DYNAMIC_NUMBERS("E4", KeyUseFor.X_DERIVE_OTHER_KEYS),
                      _E5_EMV_CHIP_CARD_MASTER_KEY_CARD_PERSONALIZATION("E5", KeyUseFor.X_DERIVE_OTHER_KEYS),
                      _E6_EMV_CHIP_CARD_MASTER_KEY_OTHER("E6", KeyUseFor.X_DERIVE_OTHER_KEYS),
                      _I0_INITIALIZATION_VECTOR_IV("I0", KeyUseFor.N_NO_SPECIAL_RESTRICTIONS_OR_NOT_APPLICABLE),
                      _K0_KEY_ENCRYPTION_OR_WRAPPING(
                                                     "K0",
                                                     KeyUseFor.B_BOTH_ENCRYPT_AND_DECRYPT,
                                                     KeyUseFor.D_DECRYPT_ONLY,
                                                     KeyUseFor.E_ENCRYPT_ONLY),
                      _K1_TR31_KEY_BLOCK_PROTECTION_KEY(
                                                        "K1",
                                                        KeyUseFor.B_BOTH_ENCRYPT_AND_DECRYPT,
                                                        KeyUseFor.D_DECRYPT_ONLY,
                                                        KeyUseFor.E_ENCRYPT_ONLY),
                      _K2_TR34_ASYMMETRIC_KEY(
                                              "K2",
                                              KeyUseFor.B_BOTH_ENCRYPT_AND_DECRYPT,
                                              KeyUseFor.D_DECRYPT_ONLY,
                                              KeyUseFor.E_ENCRYPT_ONLY),
                      _K3_ASYMMETRIC_KEY_FOR_AGREEMENT_OR_WRAPPING(
                                                                   "K3",
                                                                   KeyUseFor.B_BOTH_ENCRYPT_AND_DECRYPT,
                                                                   KeyUseFor.D_DECRYPT_ONLY,
                                                                   KeyUseFor.E_ENCRYPT_ONLY,
                                                                   KeyUseFor.X_DERIVE_OTHER_KEYS),
                      _M0_ISO_16609_MAC_ALGORITHM_1_USING_TDEA(
                                                               "M0",
                                                               KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                               KeyUseFor.G_MAC_GENERATE_ONLY,
                                                               KeyUseFor.V_MAC_VERIFY_ONLY),
                      _M1_ISO_9797_1_MAC_ALGORITHM_1(
                                                     "M1",
                                                     KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                     KeyUseFor.G_MAC_GENERATE_ONLY,
                                                     KeyUseFor.V_MAC_VERIFY_ONLY),
                      _M2_ISO_9797_1_MAC_ALGORITHM_2(
                                                     "M2",
                                                     KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                     KeyUseFor.G_MAC_GENERATE_ONLY,
                                                     KeyUseFor.V_MAC_VERIFY_ONLY),
                      _M3_ISO_9797_1_MAC_ALGORITHM_3(
                                                     "M3",
                                                     KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                     KeyUseFor.G_MAC_GENERATE_ONLY,
                                                     KeyUseFor.V_MAC_VERIFY_ONLY),
                      _M4_ISO_9797_1_MAC_ALGORITHM_4(
                                                     "M4",
                                                     KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                     KeyUseFor.G_MAC_GENERATE_ONLY,
                                                     KeyUseFor.V_MAC_VERIFY_ONLY),
                      _M5_ISO_9797_1_MAC_ALGORITHM_5(
                                                     "M5",
                                                     KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                     KeyUseFor.G_MAC_GENERATE_ONLY,
                                                     KeyUseFor.V_MAC_VERIFY_ONLY),
                      _M6_ISO_9797_1_MAC_ALGORITHM_5_CMAC(
                                                          "M6",
                                                          KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                          KeyUseFor.G_MAC_GENERATE_ONLY,
                                                          KeyUseFor.V_MAC_VERIFY_ONLY),
                      _M7_HMAC(
                               "M7",
                               KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                               KeyUseFor.G_MAC_GENERATE_ONLY,
                               KeyUseFor.V_MAC_VERIFY_ONLY),
                      _M8_ISO_9797_1_MAC_ALGORITHM_6(
                                                     "M8",
                                                     KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                     KeyUseFor.G_MAC_GENERATE_ONLY,
                                                     KeyUseFor.V_MAC_VERIFY_ONLY),
                      _P0_PIN_ENCRYPTION(
                                         "P0",
                                         KeyUseFor.B_BOTH_ENCRYPT_AND_DECRYPT,
                                         KeyUseFor.D_DECRYPT_ONLY,
                                         KeyUseFor.E_ENCRYPT_ONLY),
                      _S0_ASSYMETRIC_KEY_PAIR_DIGITAL_SIGNATURE(
                                                                "S0",
                                                                KeyUseFor.S_SIGNATURE_ONLY,
                                                                KeyUseFor.V_MAC_VERIFY_ONLY),
                      _S1_ASSYMETRIC_KEY_PAIR_CA("S1", KeyUseFor.S_SIGNATURE_ONLY, KeyUseFor.V_MAC_VERIFY_ONLY),
                      _S2_ASSYMETRIC_KEY_PAIR_NON_X_9_94(
                                                         "S2",
                                                         KeyUseFor.S_SIGNATURE_ONLY,
                                                         KeyUseFor.V_MAC_VERIFY_ONLY,
                                                         KeyUseFor.T_SIGN_AND_DECYPT,
                                                         KeyUseFor.B_BOTH_ENCRYPT_AND_DECRYPT,
                                                         KeyUseFor.D_DECRYPT_ONLY,
                                                         KeyUseFor.E_ENCRYPT_ONLY),
                      _V0_PIN_VERIFICATION_KPV_OTHER_ALGORITHM(
                                                               "V0",
                                                               KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                               KeyUseFor.G_MAC_GENERATE_ONLY,
                                                               KeyUseFor.V_MAC_VERIFY_ONLY),
                      _V1_PIN_VERIFICATION_IBM_3624(
                                                    "V1",
                                                    KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                    KeyUseFor.G_MAC_GENERATE_ONLY,
                                                    KeyUseFor.V_MAC_VERIFY_ONLY),
                      _V2_PIN_VERIFICATION_VISA_PVV(
                                                    "V2",
                                                    KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                    KeyUseFor.G_MAC_GENERATE_ONLY,
                                                    KeyUseFor.V_MAC_VERIFY_ONLY),
                      _V3_PIN_VERIFICATION_X9_132_ALGORITHM_1(
                                                              "V3",
                                                              KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                              KeyUseFor.G_MAC_GENERATE_ONLY,
                                                              KeyUseFor.V_MAC_VERIFY_ONLY),
                      _V4_PIN_VERIFICATION_X9_132_ALGORITHM_2(
                                                              "V4",
                                                              KeyUseFor.C_MAC_CALCULATE_GENERATE_OR_VERIFY,
                                                              KeyUseFor.G_MAC_GENERATE_ONLY,
                                                              KeyUseFor.V_MAC_VERIFY_ONLY);

    private String          keyUsage;
    private List<KeyUseFor> allowedUsage;

    KeyUsage(String ku, KeyUseFor... allowedUsages) {
        this.keyUsage = ku;
        this.allowedUsage = Arrays.asList(allowedUsages);
    }

    public String getUsage() {
        return keyUsage;
    }

    public boolean isAllowedUsage(KeyUseFor ku) {

        return allowedUsage.contains(ku);

    }

    public List<KeyUseFor> getAllowedusage() {
        return List.copyOf(allowedUsage);
    }

    public static Optional<KeyUsage> fromString(String temp) {

        // iterate over enums using for loop
        for (KeyUsage s : KeyUsage.values()) {
            if (temp.equals(s.getUsage())) {
                return Optional.of(s);
            }
        }
        return Optional.empty();

    }
}
