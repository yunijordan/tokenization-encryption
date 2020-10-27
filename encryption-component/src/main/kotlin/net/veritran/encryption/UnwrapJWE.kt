package net.veritran.encryption

import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers

class UnwrapJWE {
    fun execute(encryptedPayload: String, aPrivateKey: String, algorithm: String): String {
        return JweUtils.jwePayload(
            EncryptUtils.getPrivateKey(aPrivateKey, algorithm),
            encryptedPayload,
            KeyManagementAlgorithmIdentifiers.RSA_OAEP_256
        )
    }
}