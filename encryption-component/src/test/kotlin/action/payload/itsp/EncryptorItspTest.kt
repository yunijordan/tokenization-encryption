package action.payload.itsp

import net.veritran.encryption.action.payload.itsp.DecryptorItsp
import net.veritran.encryption.action.payload.itsp.EncryptorItsp
import net.veritran.encryption.infrastructure.adapter.outbound.ClassPathKeyLoaderProvider
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class EncryptorItspTest {

    @Test
    fun `encrypt itsp payload using classpath key loader`() {
        val path = "src/test/resources/certificates/test_certificate-2048.pem"
        val itspPublicKeyLoader = ClassPathKeyLoaderProvider.from(path).asItspPublicKey()
        val encryptorItsp = EncryptorItsp(itspPublicKeyLoader)
        val payload = "{\n \"param1\": \"foo\",\n \"param2\": \"bar\"\n }"

        val result = encryptorItsp.execute(payload)

        val decryptorItsp = buildDecryptor()

        Assertions.assertEquals(payload, decryptorItsp.execute(result) )
    }

    private fun buildDecryptor(): DecryptorItsp {
        val keyFilePath = "src/test/resources/keys/test_key_pkcs8-2048.der"
        val publicItspKeyLoader = ClassPathKeyLoaderProvider.from(keyFilePath).asItspPrivateKey()
        return DecryptorItsp(publicItspKeyLoader)
    }
}