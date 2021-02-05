package action.payload.visa

import net.veritran.encryption.action.payload.visa.DecryptorVisa
import net.veritran.encryption.action.payload.visa.EncryptorVisa
import net.veritran.encryption.infrastructure.adapter.outbound.classPathPkcs8RsaPrivateKeyLoader
import net.veritran.encryption.infrastructure.adapter.outbound.classPathX509PublicKeyLoader
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class EncryptorVisaTest {

    @Test
    fun `encrypt a Visa payload successfully`() {

        // given
        val encryptorVisa = EncryptorVisa(
            classPathX509PublicKeyLoader,
            classPathPkcs8RsaPrivateKeyLoader
        )
        val payload: String = "hola mundo"
        val keyName: String = "src/test/resources/visa/test1.pub"


        // when
        val result = encryptorVisa.execute(payload, keyName)
        println(result)

        // then
        val msgDecrypted = DecryptorVisa(
            classPathPkcs8RsaPrivateKeyLoader,
            classPathX509PublicKeyLoader
        )
            .execute(result, "src/test/resources/visa/test1.pkcs8")
        Assertions.assertEquals(payload, msgDecrypted)
    }
}