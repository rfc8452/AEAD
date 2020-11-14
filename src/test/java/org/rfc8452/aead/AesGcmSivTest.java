package org.rfc8452.aead;

import javax.crypto.AEADBadTagException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.GeneralSecurityException;

class AesGcmSivTest
{

    @Test
    void shouldProduceDecipheredThatEqualsToInitialPlaintext16S() throws GeneralSecurityException {
        AEAD aead = new AesGcmSiv("00000000000000000000000000000000");
        final byte[] plaintext = new byte[] {1, 1};
        final byte[] aad = new byte[] {2, 2};
        final byte[] ciphertext = aead.seal(plaintext, aad);
        final byte[] deciphered = aead.open(ciphertext, aad);
        Assertions.assertArrayEquals(plaintext, deciphered);
    }

    @Test
    void shouldProduceDecipheredThatEqualsToInitialPlaintext16B() throws GeneralSecurityException {
        AEAD aead = new AesGcmSiv(new byte[] {
                1, 1, 1, 1,
                1, 1, 1, 1,
                1, 1, 1, 1,
                1, 1, 1, 1
        });
        final byte[] plaintext = new byte[] {1, 1};
        final byte[] aad = new byte[] {2, 2};
        final byte[] ciphertext = aead.seal(plaintext, aad);
        final byte[] deciphered = aead.open(ciphertext, aad);
        Assertions.assertArrayEquals(plaintext, deciphered);
    }

    @Test
    void shouldProduceDecipheredThatEqualsToInitialPlaintext32B() throws GeneralSecurityException {
        AEAD aead = new AesGcmSiv(new byte[] {
                1, 1, 1, 1,
                1, 1, 1, 1,
                1, 1, 1, 1,
                1, 1, 1, 1,

                1, 1, 1, 1,
                1, 1, 1, 1,
                1, 1, 1, 1,
                1, 1, 1, 1
        });
        final byte[] plaintext = new byte[] {1, 1};
        final byte[] aad = new byte[] {2, 2};
        final byte[] ciphertext = aead.seal(plaintext, aad);
        final byte[] deciphered = aead.open(ciphertext, aad);
        Assertions.assertArrayEquals(plaintext, deciphered);
    }

    @Test
    void shouldFailOnInvalidAad() throws GeneralSecurityException {
        AEAD aead = new AesGcmSiv("01000000000000000000000000000000");
        final byte[] plaintext = new byte[] {1, 1};
        final byte[] aad = new byte[] {2, 2};
        final byte[] invalidAad = new byte[] {3, 3};
        Assertions.assertThrows(AEADBadTagException.class, () -> aead.open(aead.seal(plaintext, aad), invalidAad));
    }

    @Test
    void shouldForgetKeyAfterKeyReset() throws GeneralSecurityException {
        AEAD aead = new AesGcmSiv("00000000000000000000000000000000");
        final byte[] plaintext = new byte[] {1, 1};
        final byte[] aad = new byte[] {2, 2};
        final byte[] ciphertext = aead.seal(plaintext, aad);
        aead.resetKey();
        Assertions.assertThrows(AEADBadTagException.class, () -> aead.open(ciphertext, aad));
    }

}