package utils

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Parser

import net.veritran.encryption.domain.algorithm.CipherTransformations
import net.veritran.encryption.domain.algorithm.HashAlgorithms
import net.veritran.encryption.infrastructure.EncryptUtils
import net.veritran.encryption.infrastructure.StringUtils

import java.nio.file.Files
import java.nio.file.Paths
import java.io.FileInputStream

import java.security.cert.CertificateFactory

object MastercardFixture {

    const val keyFilePath = "src/test/resources/digital-enablement-sandbox-decryption-key.key"

    val encryptedBody = Parser().parse("src/test/resources/mdes/encryptedPayload.json") as JsonObject
    val aDecryptedBody = Parser().parse("src/test/resources/mdes/decryptedPayload.json") as JsonObject

    val aTSPKey: ByteArray = Files.readAllBytes(Paths.get("src/test/resources/keys/test_key_pkcs8-2048.der"))

    val aCipherTransformation = CipherTransformations.AES_CBC_PKCS5PADDING.value

    val aKey: String = generateKey()

    private fun generateKey(): String {
        val factory = CertificateFactory.getInstance("X.509")
        val fileInputStream = FileInputStream("src/test/resources/certificates/test_certificate-2048.pem")
        val generatedCertificate = factory.generateCertificate(fileInputStream)
        val publicKey = generatedCertificate.publicKey
        val secretKey = EncryptUtils.generateSecretKey()
        val oaepPaddingDigestAlgorithm = HashAlgorithms.SHA_256.value
        val wrappedSecretKey = EncryptUtils.wrapSecretKey(publicKey, secretKey, oaepPaddingDigestAlgorithm)
        return StringUtils.hexEncode(wrappedSecretKey)
    }

}