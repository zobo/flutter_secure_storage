package com.it_nomads.fluttersecurestorage.ciphers;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class CipherAlgorithmTest {

    // -------------------------------------------------------------------------
    // KeyCipherAlgorithm.fromString
    // -------------------------------------------------------------------------

    @Test
    public void keyCipher_fromString_RSA_ECB_OAEPwithSHA_256andMGF1Padding() {
        assertEquals(
            KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding,
            KeyCipherAlgorithm.fromString("RSA_ECB_OAEPwithSHA_256andMGF1Padding")
        );
    }

    @Test
    public void keyCipher_fromString_AES_GCM_NoPadding() {
        assertEquals(KeyCipherAlgorithm.AES_GCM_NoPadding, KeyCipherAlgorithm.fromString("AES_GCM_NoPadding"));
    }

    @Test
    public void keyCipher_fromString_legacyBiometricName_mapsToAES_GCM() {
        // Legacy name used before the rename — must still resolve to the correct value
        assertEquals(
            KeyCipherAlgorithm.AES_GCM_NoPadding,
            KeyCipherAlgorithm.fromString("AES_GCM_NoPadding_BIOMETRIC")
        );
    }

    @Test
    public void keyCipher_fromString_unknownName_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> KeyCipherAlgorithm.fromString("UNKNOWN_ALGORITHM"));
    }

    @Test
    public void keyCipher_fromString_emptyString_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> KeyCipherAlgorithm.fromString(""));
    }

    @Test
    public void keyCipher_fromString_legacyPKCS1_resolvesToLegacyEnumValue() {
        // RSA_ECB_PKCS1Padding is the legacy key cipher used by v9.x and earlier.
        // It must resolve to its own enum value (not OAEP) so v9 data can still
        // be decrypted and migrated to the current key cipher.
        assertEquals(
            KeyCipherAlgorithm.RSA_ECB_PKCS1Padding,
            KeyCipherAlgorithm.fromString("RSA_ECB_PKCS1Padding")
        );
    }

    // -------------------------------------------------------------------------
    // StorageCipherAlgorithm.fromString
    // -------------------------------------------------------------------------

    @Test
    public void storageCipher_fromString_AES_GCM_NoPadding() {
        assertEquals(StorageCipherAlgorithm.AES_GCM_NoPadding, StorageCipherAlgorithm.fromString("AES_GCM_NoPadding"));
    }

    @Test
    public void storageCipher_fromString_legacyBiometricName_mapsToAES_GCM() {
        // Legacy name used before the rename — must still resolve to the correct value
        assertEquals(
            StorageCipherAlgorithm.AES_GCM_NoPadding,
            StorageCipherAlgorithm.fromString("AES_GCM_NoPadding_BIOMETRIC")
        );
    }

    @Test
    public void storageCipher_fromString_unknownName_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> StorageCipherAlgorithm.fromString("UNKNOWN_ALGORITHM"));
    }

    @Test
    public void storageCipher_fromString_emptyString_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> StorageCipherAlgorithm.fromString(""));
    }

    @Test
    public void storageCipher_fromString_legacyCBC_resolvesToLegacyEnumValue() {
        // AES_CBC_PKCS7Padding is the legacy storage cipher used by v9.x and earlier.
        // It must resolve to its own enum value (not GCM) so v9 data can still
        // be decrypted and migrated to the current storage cipher.
        assertEquals(
            StorageCipherAlgorithm.AES_CBC_PKCS7Padding,
            StorageCipherAlgorithm.fromString("AES_CBC_PKCS7Padding")
        );
    }

    // -------------------------------------------------------------------------
    // Enum completeness — guards against accidental removal of values
    // -------------------------------------------------------------------------

    @Test
    public void keyCipher_hasExpectedNumberOfValues() {
        assertEquals(3, KeyCipherAlgorithm.values().length);
    }

    @Test
    public void storageCipher_hasExpectedNumberOfValues() {
        assertEquals(2, StorageCipherAlgorithm.values().length);
    }
}
