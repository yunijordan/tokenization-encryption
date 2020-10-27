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
        algorithm: String,
        algorithmIdentifier: String,
        transformation: String,
        hashAlgorithm: String
    ): String {
        val jwePublicKey = getPublicKey(publicKey, algorithm)
        val signedMessage = Base64.getEncoder().encodeToString(signMessage(message, privateKey, algorithm, transformation, hashAlgorithm))
        return jweCompactSerialization(jwePublicKey, signedMessage, algorithmIdentifier)
    }
}