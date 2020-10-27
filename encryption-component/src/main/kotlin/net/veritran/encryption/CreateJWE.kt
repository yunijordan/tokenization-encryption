package net.veritran.encryption

import net.veritran.encryption.EncryptUtils.getPublicKey
import net.veritran.encryption.EncryptUtils.signMessage
import net.veritran.encryption.JweUtils.jweCompactSerialization
import java.util.*

class CreateJWE {
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