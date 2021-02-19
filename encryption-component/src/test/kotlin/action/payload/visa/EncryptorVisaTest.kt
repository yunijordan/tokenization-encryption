package action.payload.visa

import net.veritran.encryption.action.payload.visa.DecryptorVisa
import net.veritran.encryption.action.payload.visa.EncryptorVisa
import net.veritran.encryption.infrastructure.adapter.outbound.ClassPathKeyLoaderProvider
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class EncryptorVisaTest {

    @Test
    fun `encrypt a Visa payload successfully`() {

        // given
        val payload: String = "{\n" +
                "\t\"primaryAccountNumber\": \"1234\",\n" +
                "\t\"name\": \"dummy\",\n" +
                "\t\"highValueCustomer\": \"1234\",\n" +
                "\t\"riskAssessmentScore\": \"risk-1\",\n" +
                "\t\"expirationDate\": {\n" +
                "\t\t\"month\": \"jan\",\n" +
                "\t\t\"year\": \"1990\"\n" +
                "\t}\n" +
                "}"
        val publicKey = "src/test/resources/visa/test1.pub"
        val signerKey = "src/test/resources/visa/test1.pkcs8"

        val encryptorVisa = EncryptorVisa(
            ClassPathKeyLoaderProvider.from(publicKey).asVisaPublicKey(),
            ClassPathKeyLoaderProvider.from(signerKey).asVisaSingerKey()
        )

        // when
        val result = encryptorVisa.execute(payload)
        // then
        val msgDecrypted = decrypt(result)
        Assertions.assertEquals(payload, msgDecrypted)
    }

    private fun decrypt(result: String): String {
        val privateKeyName = "src/test/resources/visa/test1.pkcs8"
        val verifierKey = "src/test/resources/visa/test1.pub"
        val decryptorVisa = DecryptorVisa(
            ClassPathKeyLoaderProvider.from(privateKeyName).asVisaPrivateKey(),
            ClassPathKeyLoaderProvider.from(verifierKey).asVisaVerifierKey()
        )
        return decryptorVisa.execute(result)
    }
}