package net.veritran.encryption.infrastructure

import org.jose4j.jwa.AlgorithmConstraints
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers
import org.jose4j.jwe.JsonWebEncryption
import org.jose4j.lang.JoseException

import java.security.Key
import java.security.SecureRandom

object JweUtils {

    fun jweCompactSerialization(
        publicKey: Key,
        message: String,
        algorithmIdentifiers: String
    ): String {
        return try {
            val jwe = JsonWebEncryption()
            jwe.algorithmHeaderValue = algorithmIdentifiers
            jwe.encryptionMethodHeaderParameter = ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256
            jwe.payload = message
            jwe.key = publicKey
            jwe.iv = SecureRandom.getInstance("SHA1PRNG").generateSeed(16)
            jwe.compactSerialization
        } catch (e: Exception) {
            throw RuntimeException(e)
        }
    }

    fun jwePayload(privateKey: Key, serializedJwe: String, algorithms: String): String {
        try {
            val jwe = JsonWebEncryption()
            jwe.setAlgorithmConstraints(
                AlgorithmConstraints(
                    AlgorithmConstraints.ConstraintType.PERMIT,
                    algorithms
                )
            )
            jwe.setContentEncryptionAlgorithmConstraints(
                AlgorithmConstraints(
                    AlgorithmConstraints.ConstraintType.PERMIT,
                    ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256
                )
            )
            jwe.key = privateKey
            jwe.compactSerialization = serializedJwe
            return jwe.payload
        } catch (e: JoseException) {
            e.printStackTrace()
        }
        return ""
    }

}