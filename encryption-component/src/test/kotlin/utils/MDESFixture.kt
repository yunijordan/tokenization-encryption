package utils

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Parser

import net.veritran.encryption.domain.algorithm.CipherTransformations
import net.veritran.encryption.domain.algorithm.HashAlgorithms
import net.veritran.encryption.infrastructure.EncryptUtils

import java.security.SecureRandom

object MDESFixture {

    const val keyFilePath = "src/test/resources/digital-enablement-sandbox-decryption-key.key"

    val encryptedBody = Parser().parse("src/test/resources/mdes/encryptedPayload.json") as JsonObject
    val aDecryptedBody = Parser().parse("src/test/resources/mdes/decryptedPayload.json") as JsonObject

    val aCipherTransformation = CipherTransformations.AES_CBC_PKCS5PADDING.value

    val aHashingAlgorithm = HashAlgorithms.SHA_256.value // TODO internal impl
    val anInitialVector = EncryptUtils.generateIv(ivBytes()) // TODO internal impl

    const val aKey: String = "" //TODO Temporal

    private fun generateKey() {
        // Generate AES Secret Key generateSecretKey()
        // Wrap wrapSecretKey(config, secretKey);
        // Encode encodeBytes(encryptedSecretKeyBytes, config.fieldValueEncoding);
    }

    private fun ivBytes(): ByteArray { //TODO internal impl
        val secureRandom = SecureRandom.getInstance("SHA1PRNG")
        val ivBytes = ByteArray(16)
        secureRandom.nextBytes(ivBytes)
        return ivBytes
    }


}