package org.rfc8452.aead;

import java.security.GeneralSecurityException;

public interface AEAD {

    byte[] seal(byte[] plaintext, byte[] aad, byte[] nonce) throws GeneralSecurityException;
    byte[] open(byte[] ciphertext, byte[] aad, byte[] nonce) throws GeneralSecurityException;

    byte[] seal(byte[] plaintext, byte[] aad) throws GeneralSecurityException;
    byte[] open(byte[] ciphertext, byte[] aad) throws GeneralSecurityException;

    String seal(String plaintextHexString, String aadHexString, String nonceHexString)
            throws GeneralSecurityException;
    String open(String ciphertextHexString, String aadHexString, String nonceHexString)
            throws GeneralSecurityException;

    void resetKey() throws GeneralSecurityException;
}
