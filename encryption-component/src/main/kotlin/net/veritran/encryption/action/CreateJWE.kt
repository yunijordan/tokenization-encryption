package net.veritran.encryption.action

import net.veritran.encryption.infrastructure.EncryptUtils.getPublicKey
import net.veritran.encryption.infrastructure.EncryptUtils.signMessage
import net.veritran.encryption.infrastructure.JweUtils.jweCompactSerialization
import java.util.*

object CreateJWE {
    fun execute(
        publicKey: String,
        privateKey: String,
        message: String,
        keyAlgorithm: String,
        algorithmIdentifier: String,
        cipherTransformation: String,
        hashAlgorithm: String
    ): String {
        val jwePublicKey = getPublicKey(publicKey, keyAlgorithm)
        val signedMessage = Base64.getEncoder().encodeToString(
            signMessage(message, privateKey, keyAlgorithm, cipherTransformation, hashAlgorithm))
        return jweCompactSerialization(jwePublicKey, signedMessage, algorithmIdentifier)
    }
}