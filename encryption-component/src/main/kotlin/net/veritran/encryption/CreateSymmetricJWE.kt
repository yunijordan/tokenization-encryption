package net.veritran.encryption

import net.veritran.encryption.JweUtils.jweCompactSerialization
import org.jose4j.keys.AesKey
import java.security.Key
import java.util.*

class CreateSymmetricJWE {
    fun execute(
        symmetricKey: String?,
        message: String?,
        keyManagementAlgorithmIdentifier: String?
    ): String {
        val jwePublicKey: Key = AesKey(Base64.getDecoder().decode(symmetricKey))
        return jweCompactSerialization(jwePublicKey, message!!, keyManagementAlgorithmIdentifier!!)
    }
}