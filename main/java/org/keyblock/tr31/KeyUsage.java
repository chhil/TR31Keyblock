package org.keyblock.tr31;

public enum KeyUsage {

                      _B0_BDK_Base_Derivation_Key("B0"),
                      _C0_CVK_Card_Verification_Key("C0"),
                      _D0_Data_Encryption("D0"),
                      _E0_EMV_chip_card_Master_Key_Application_cryptograms("E0"),
                      _E1_EMV_chip_card_Master_Key_Secure_Messaging_for_Confidentiality("E1"),
                      _E2__EMV_chip_card_Master_Key_Secure_Messaging_for_Integrity("E2"),
                      _E3_EMV_chip_card_Master_Key_Data_Authentication_Code("E3"),
                      _E4_EMV_chip_card_Master_Key_Dynamic_Numbers("E4"),
                      _E5_EMV_chip_card_Master_Key_Card_Personalization("E5"),
                      _E6_EMV_chip_card_Master_Key_Other("E6"),
                      _I0_Initialization_Vector_IV("I0"),
                      _K0_Key_Encryption_or_wrapping("K0"),
                      _M0_ISO_16609_MAC_algorithm_1_using_TDEA("M0"),
                      _M1_ISO_9797_1_MAC_Algorithm_1("M1"),
                      _M2_ISO_9797_1_MAC_Algorithm_2("M2"),
                      _M3_ISO_9797_1_MAC_Algorithm_3("M3"),
                      _M4_ISO_9797_1_MAC_Algorithm_4("M4"),
                      _M5_ISO_9797_1_MAC_Algorithm_5("M5"),
                      _P0_PIN_Encryption("P0"),
                      _V0_PIN_verification_KPV_other_algorithm("V0"),
                      _V1_PIN_verification_IBM_3624("V1"),
                      _V2_PIN_Verification_VISA_PVV("V2");

    private String keyUsage;

    KeyUsage(String ku) {
        this.keyUsage = ku;// TODO Auto-generated constructor stub
    }

    public String getUsage() {
        return keyUsage;
    }
}
