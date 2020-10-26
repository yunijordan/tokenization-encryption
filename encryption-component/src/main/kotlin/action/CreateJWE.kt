package action

import infrastructure.EncryptUtils.getPublicKey
import infrastructure.EncryptUtils.signMessage
import infrastructure.JweUtils.jweCompactSerialization
import java.util.*

class CreateJWE {
    fun execute(
        publicKey: String,
        privateKey: String,
        message: String,
        algorithmIdentifier: String
    ): String {
        val jwePublicKey = getPublicKey(publicKey)
        val signedMessage = Base64.getEncoder().encodeToString(signMessage(message, privateKey))
        return jweCompactSerialization(jwePublicKey, signedMessage, algorithmIdentifier)
    }
}