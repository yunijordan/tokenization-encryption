package action

import infrastructure.EncryptUtils
import infrastructure.JweUtils
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers

class UnwrapJWE {
    fun execute(encryptedPayload: String, aPrivateKey: String): String {
        return JweUtils.jwePayload(
            EncryptUtils.getPrivateKey(aPrivateKey),
            encryptedPayload,
            KeyManagementAlgorithmIdentifiers.RSA_OAEP_256
        )
    }
}