package org.rfc8452.aead;

import java.util.Formatter;
import java.util.Scanner;

public class Conversion
{

    static byte[] hexStringToBytes(final String hexString)
    {
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length() / 2; i++)
        {
            String chunk = hexString.substring(i * 2, i * 2 + 2);
            bytes[i] = (byte) new Scanner(chunk).nextInt(16);
        }
        return bytes;
    }

    static String bytesToHexString(final byte[] bytes)
    {
        Formatter formatter = new Formatter();
        for (byte b : bytes)
        {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

}
