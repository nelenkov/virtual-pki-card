package org.nick.hce.pki;

public class ISO7816 {

    private ISO7816() {
    }

    // ISO 7816 subset
    public static final byte CLA_ISO7816 = 0x00;
    public static final byte INS_SELECT = (byte) 0xA4;

    public static final int OFFSET_CLA = 0;
    public static final int OFFSET_INS = 1;
    public static final int OFFSET_P1 = 2;
    public static final int OFFSET_P2 = 3;
    public static final int OFFSET_LC = 4;
    public static final int OFFSET_CDATA = 5;
    public static final int OFFSET_EXT_CDATA = 7;

    public static final short SW_SUCCESS = (short) 0x9000;
    public static final short SW_APPLET_SELECT_FAILED = 0x6999;
    public static final short SW_CLA_NOT_SUPPORTED = 0x6E00;
    public static final short SW_INS_NOT_SUPPORTED = 0x6D00;
    public static final short SW_COMMAND_NOT_ALLOWED = 0x6986;
    public static final short SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982;
    public static final short SW_DATA_INVALID = 0x6984;
    public static final short SW_CONDITIONS_NOT_SATISFIED = 0x6985;
    public static final short SW_INCORRECT_P1P2 = 0x6A86;
    public static final short SW_WRONG_LENGTH = 0x6700;
    public static final short SW_WRONG_DATA = 0x6A80;
    public static final short FILE_NOT_FOUND = 0x6A82;
    public static final short SW_WRONG_P1P2 = 0x6B00;
    public static final short SW_UNKNOWN = 0x6F00;


}
