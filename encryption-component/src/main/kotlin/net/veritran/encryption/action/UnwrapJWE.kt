package net.veritran.encryption.action

import net.veritran.encryption.infrastructure.EncryptUtils
import net.veritran.encryption.infrastructure.JweUtils
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