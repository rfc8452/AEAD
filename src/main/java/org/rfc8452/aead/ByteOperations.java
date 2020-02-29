package org.rfc8452.aead;

public class ByteOperations
{
    static void inPlaceUpdate(byte[] b, final int n)
    {
        b[0] = (byte) n;
        b[1] = (byte) (n >> 8);
        b[2] = (byte) (n >> 16);
        b[3] = (byte) (n >> 24);
    }

    static void inPlaceUpdate(byte[] b, final long n, final int offset)
    {
        b[offset] = (byte) n;
        b[1 + offset] = (byte) (n >> 8);
        b[2 + offset] = (byte) (n >> 16);
        b[3 + offset] = (byte) (n >> 24);
        b[4 + offset] = (byte) (n >> 32);
        b[5 + offset] = (byte) (n >> 40);
        b[6 + offset] = (byte) (n >> 48);
        b[7 + offset] = (byte) (n >> 56);
    }
}
