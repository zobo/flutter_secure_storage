package com.it_nomads.fluttersecurestorage.ciphers;

import android.os.Build;

public enum KeyCipherAlgorithm {
    // Legacy algorithm used by v9.x and earlier. Kept so data encrypted with it can still be
    // decrypted and migrated to the current key cipher; must never be used to encrypt new data.
    RSA_ECB_PKCS1Padding(KeyCipherImplementationRSA18::new, 1),
    RSA_ECB_OAEPwithSHA_256andMGF1Padding(KeyCipherImplementationRSAOAEP::new, Build.VERSION_CODES.M),
    AES_GCM_NoPadding(KeyCipherImplementationAES23::new, Build.VERSION_CODES.M); // Renamed from AES_GCM_NoPadding_BIOMETRIC
    final KeyCipherFunction keyCipher;
    final int minVersionCode;

    KeyCipherAlgorithm(KeyCipherFunction keyCipher, int minVersionCode) {
        this.keyCipher = keyCipher;
        this.minVersionCode = minVersionCode;
    }

    // Migration support: Map legacy names to current values
    public static KeyCipherAlgorithm fromString(String name) {
        if ("AES_GCM_NoPadding_BIOMETRIC".equals(name)) {
            return AES_GCM_NoPadding; // Renamed in v10.1
        }
        return valueOf(name);
    }
}
