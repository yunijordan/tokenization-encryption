package net.veritran.encryption.action

import net.veritran.encryption.domain.algorithm.AlgorithmIdentifiers
import net.veritran.encryption.infrastructure.EncryptUtils
import net.veritran.encryption.infrastructure.JweUtils

class UnwrapJWE {
    fun execute(
            encryptedPayload: String,
            aPrivateKey: String,
            keyAlgorithm: String
    ): String {
        return JweUtils.jwePayload(
            EncryptUtils.getPrivateKey(aPrivateKey, keyAlgorithm),
            encryptedPayload,
            AlgorithmIdentifiers.RSA_OAEP_256.value
        )
    }
}