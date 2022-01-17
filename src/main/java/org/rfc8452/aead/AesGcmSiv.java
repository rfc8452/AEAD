package org.rfc8452.aead;

import org.rfc8452.authenticator.Polyval;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class AesGcmSiv implements AEAD
{
    static final int AES_BLOCK_SIZE = 16;
    private static final int NONCE_BYTE_LENGTH = 12;

    private final byte[] key;

    public AesGcmSiv(final byte[] key)
    {
        this.key = key;
    }

    public AesGcmSiv(final String keyHexString)
    {
        this.key = Conversion.hexStringToBytes(keyHexString);
    }

    private static Cipher initAesEcbNoPaddingCipher(final byte[] key) throws GeneralSecurityException
    {
        if (!((key.length == 16) || (key.length == 32)))
        {
            throw new InvalidKeyException(
                    String.format("Key length is %d, expected length is 16 or 32 bytes", key.length));
        }
        final Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        return cipher;
    }

    @Override
    public byte[] seal(final byte[] plaintext, final byte[] aad, final byte[] nonce) throws GeneralSecurityException
    {
        final byte[] authenticationKey = deriveKey(key, nonce, 0, 1);
        final byte[] encryptionKey = deriveKey(key, nonce, 2, key.length == 16 ? 3 : 5);
        final byte[] tag = getTag(encryptionKey, authenticationKey, plaintext, aad, nonce);
        final byte[] ciphertext = aesCtr(encryptionKey, tag, plaintext);
        final byte[] tagWithCiphertext = new byte[tag.length + ciphertext.length];
        System.arraycopy(tag, 0, tagWithCiphertext, plaintext.length, tag.length);
        System.arraycopy(ciphertext, 0, tagWithCiphertext, 0, ciphertext.length);
        return tagWithCiphertext;
    }

    public byte[] seal(final byte[] plaintext, final byte[] aad) throws GeneralSecurityException
    {
        final byte[] nonce = new byte[NONCE_BYTE_LENGTH];
        SecureRandom.getInstanceStrong().nextBytes(nonce);

        final byte[] ciphertext = seal(plaintext, aad, nonce);
        final byte[] nonceWithCipherText = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, nonceWithCipherText, 0, nonce.length);
        System.arraycopy(ciphertext, 0, nonceWithCipherText, nonce.length, ciphertext.length);
        return nonceWithCipherText;
    }

    @Override
    public String seal(final String plaintextHexString, final String aadHexString, final String nonceHexString)
            throws GeneralSecurityException
    {
        final byte[] plaintext = Conversion.hexStringToBytes(plaintextHexString);
        final byte[] aad = Conversion.hexStringToBytes(aadHexString);
        final byte[] nonce = Conversion.hexStringToBytes(nonceHexString);
        return Conversion.bytesToHexString(seal(plaintext, aad, nonce));
    }

    @Override
    public byte[] open(final byte[] ciphertext, final byte[] aad, final byte[] nonce) throws GeneralSecurityException
    {
        final byte[] tag = new byte[AES_BLOCK_SIZE];
        final byte[] plainText = new byte[ciphertext.length - AES_BLOCK_SIZE];
        System.arraycopy(ciphertext, 0, plainText, 0, plainText.length);
        System.arraycopy(ciphertext, plainText.length, tag, 0, tag.length);

        final byte[] authenticationKey = deriveKey(key, nonce, 0, 1);
        final byte[] encryptionKey = deriveKey(key, nonce, 2, key.length == 16 ? 3 : 5);

        final byte[] deciphered = aesCtr(encryptionKey, tag, plainText);
        final byte[] actual = getTag(encryptionKey, authenticationKey, deciphered, aad, nonce);

        if (MessageDigest.isEqual(tag, actual))
        {
            return deciphered;
        }
        return null;
    }

    @Override
    public byte[] open(final byte[] nonceWithCiphertext, final byte[] aad) throws GeneralSecurityException
    {
        if (nonceWithCiphertext.length < NONCE_BYTE_LENGTH)
        {
            return null;
        }
        final byte[] nonce = new byte[NONCE_BYTE_LENGTH];
        final byte[] ciphertext = new byte[nonceWithCiphertext.length - NONCE_BYTE_LENGTH];
        System.arraycopy(nonceWithCiphertext, 0, nonce, 0, nonce.length);
        System.arraycopy(nonceWithCiphertext, nonce.length, ciphertext, 0, ciphertext.length);
        return open(ciphertext, aad, nonce);
    }

    @Override
    public String open(final String ciphertextHexString,
                       final String aadHexString, final String nonceHexString)
            throws GeneralSecurityException
    {
        final byte[] ciphertext = Conversion.hexStringToBytes(ciphertextHexString);
        final byte[] aad = Conversion.hexStringToBytes(aadHexString);
        final byte[] nonce = Conversion.hexStringToBytes(nonceHexString);
        final byte[] plaintext = open(ciphertext, aad, nonce);
        if (null == plaintext)
        {
            return null;
        }
        return Conversion.bytesToHexString(plaintext);
    }

    private static byte[] getTag(final byte[] encryptionKey, final byte[] authenticationKey,
                                 final byte[] plaintext, final byte[] aad, final byte[] nonce)
            throws GeneralSecurityException
    {
        if (nonce.length != NONCE_BYTE_LENGTH)
        {
            throw new GeneralSecurityException("Expected nonce length is 12 bytes");
        }
        final byte[] aadPlaintextLengths = new byte[AES_BLOCK_SIZE];
        ByteOperations.inPlaceUpdate(aadPlaintextLengths, (long) aad.length * 8, 0);
        ByteOperations.inPlaceUpdate(aadPlaintextLengths, (long) plaintext.length * 8, 8);

        final Polyval authenticator = new Polyval(authenticationKey);
        authenticator.update(aad);
        authenticator.update(plaintext);
        authenticator.update(aadPlaintextLengths);
        final byte[] digest = authenticator.digest();
        for (int i = 0; i < nonce.length; i++)
        {
            digest[i] ^= nonce[i];
        }
        digest[digest.length - 1] &= (byte) ~0x80;
        final Cipher cipher = initAesEcbNoPaddingCipher(encryptionKey);
        cipher.update(digest, 0, digest.length, digest, 0);
        return digest;
    }

    private static byte[] deriveKey(final byte[] parentKey, final byte[] nonce,
                                    final int counterStartValue, final int counterEndValue)
            throws GeneralSecurityException
    {
        if (nonce.length != NONCE_BYTE_LENGTH)
        {
            throw new GeneralSecurityException("Expected nonce length is 12 bytes");
        }
        final Cipher cipher = initAesEcbNoPaddingCipher(parentKey);
        final byte[] counter = new byte[AES_BLOCK_SIZE];
        System.arraycopy(nonce, 0, counter, counter.length - nonce.length, nonce.length);
        final int counterLength = (counterEndValue - counterStartValue + 1) * 8;
        final byte[] key = new byte[counterLength];
        final byte[] block = new byte[AES_BLOCK_SIZE];
        for (int i = counterStartValue; i <= counterEndValue; i++)
        {
            ByteOperations.inPlaceUpdate(counter, i);
            cipher.update(counter, 0, AES_BLOCK_SIZE, block, 0);
            System.arraycopy(block, 0, key, (i - counterStartValue) * 8, 8);
        }
        return key;
    }

    private static byte[] aesCtr(final byte[] encryptionKey, final byte[] tag, final byte[] input)
            throws GeneralSecurityException
    {
        final byte[] result = new byte[input.length];
        final byte[] counter = Arrays.copyOf(tag, tag.length);
        final byte[] key = new byte[AES_BLOCK_SIZE];
        final Cipher cipher = initAesEcbNoPaddingCipher(encryptionKey);
        counter[counter.length - 1] |= (byte) 0x80;
        for (int i = 0; i < input.length; i += AES_BLOCK_SIZE)
        {
            cipher.update(counter, 0, counter.length, key, 0);
            for (int j = 0; j < Math.min(AES_BLOCK_SIZE, input.length - i); j++)
            {
                result[i + j] = (byte) (input[i + j] ^ key[j]);
            }
            for (int k=0; k < 4; k++)
            {
                if (++counter[k] != 0)
                {
                    break;
                }
            }
        }
        return result;
    }

    @Override
    public void resetKey() throws GeneralSecurityException
    {
        SecureRandom.getInstanceStrong().nextBytes(key);
    }
}
