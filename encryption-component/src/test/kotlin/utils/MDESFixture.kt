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
import java.lang.IllegalArgumentException

import java.security.cert.CertificateFactory
import java.security.spec.InvalidKeySpecException

import java.security.spec.PKCS8EncodedKeySpec

import java.security.KeyFactory

import java.security.GeneralSecurityException

import java.security.PrivateKey





object MDESFixture {

    const val keyFilePath = "src/test/resources/digital-enablement-sandbox-decryption-key.key"

    val encryptedBody = Parser().parse("src/test/resources/mdes/encryptedPayload.json") as JsonObject
    val aDecryptedBody = Parser().parse("src/test/resources/mdes/decryptedPayload.json") as JsonObject
    val aTSPKey = getTspKey()

    private fun getTspKey(): ByteArray {
        val path = Paths.get("src/test/resources/keys/test_key_pkcs8-2048.der")
        return Files.readAllBytes(path)
    }

    val aCipherTransformation = CipherTransformations.AES_CBC_PKCS5PADDING.value

    val aKey: String = getKey()

    private fun getKey(): String {
        val factory = CertificateFactory.getInstance("X.509")
        val fileInputStream = FileInputStream("src/test/resources/certificates/test_certificate-2048.pem")
        val generatedCertificate = factory.generateCertificate(fileInputStream)
        val publicKey = generatedCertificate.publicKey
        val secretKey = EncryptUtils.generateSecretKey()
        val oaepPaddingDigestAlgorithm = HashAlgorithms.SHA_256.value
        val wrapedSecretKey = EncryptUtils.wrapSecretKey(publicKey, secretKey, oaepPaddingDigestAlgorithm)
        return StringUtils.hexEncode(wrapedSecretKey)
    }

}