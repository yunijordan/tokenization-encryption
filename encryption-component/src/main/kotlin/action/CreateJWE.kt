package action

import infrastructure.EncryptUtils.getPublicKey
import infrastructure.EncryptUtils.sign
import infrastructure.JweUtils.jweCompactSerialization
import java.util.*

class CreateJWE {
    fun execute(
        publicKey: String,
        privateKey: String,
        message: String,
        keyManagementAlgorithmIdentifier: String
    ): String {
        val jwePublicKey = getPublicKey(publicKey)
        val signedMessage = Base64.getEncoder().encodeToString(sign(message, privateKey))
        return jweCompactSerialization(jwePublicKey, signedMessage, keyManagementAlgorithmIdentifier)
    }
}