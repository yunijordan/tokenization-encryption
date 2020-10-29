package net.veritran.encryption.action

import net.veritran.encryption.infrastructure.AlgorithmIdentifier
import net.veritran.encryption.infrastructure.EncryptUtils
import net.veritran.encryption.infrastructure.JweUtils

class UnwrapJWE {
    fun execute(
        encryptedPayload: String,
        aPrivateKey: String,
        algorithm: String
    ): String {
        return JweUtils.jwePayload(
            EncryptUtils.getPrivateKey(aPrivateKey, algorithm),
            encryptedPayload,
            AlgorithmIdentifier.RSA_OAEP_256.value
        )
    }
}