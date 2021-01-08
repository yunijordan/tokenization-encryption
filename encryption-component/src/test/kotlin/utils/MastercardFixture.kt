package utils

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Parser
import net.veritran.encryption.domain.encoding.WrapperOaepWithMgf1WhichUsesSha256MD
import net.veritran.encryption.domain.encoding.classPathX509CertificateFinder
import net.veritran.encryption.infrastructure.EncryptUtils
import net.veritran.encryption.infrastructure.StringUtils
import java.nio.file.Files
import java.nio.file.Paths

object MastercardFixture {

    const val keyFilePath = "src/test/resources/digital-enablement-sandbox-decryption-key.key"

    val encryptedBody = Parser().parse("src/test/resources/mdes/encryptedPayload.json") as JsonObject
    val aDecryptedBody = Parser().parse("src/test/resources/mdes/decryptedPayload.json") as JsonObject

    val aTSPKey: ByteArray = Files.readAllBytes(Paths.get("src/test/resources/keys/test_key_pkcs8-2048.der"))

    val aKey: String = generateKey()

    private fun generateKey(): String {
        val publicKey = classPathX509CertificateFinder.find(
            "src/test/resources/certificates/test_certificate-2048.pem"
        )
        val secretKey = EncryptUtils.generateSecretKey()
        val wrappedSecretKey = WrapperOaepWithMgf1WhichUsesSha256MD(publicKey).use(secretKey)
        return StringUtils.hexEncode(wrappedSecretKey)
    }

}