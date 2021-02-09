package action.payload.visa

import net.veritran.encryption.action.payload.visa.DecryptorVisa
import net.veritran.encryption.infrastructure.adapter.outbound.ClassPathKeyLoaderProvider
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class DecryptorVisaTest {

    @Test
    fun `decrypt a visa payload successfully`() {
        //given
        val encryptedAndSignedMessage = "eyJraWQiOiI3WkVJVkMxNkRHUkRRS1daRUUzWDExTGVKTURoeXFRdThRMWN0bnA0YnlseVFKQ3N3IiwiY3R5IjoiSldFIiwidHlwIjoiSk9TRSIsImFsZyI6IlBTMjU2In0.ZXlKcmFXUWlPaUkzV2tWSlZrTXhOa1JIVWtSUlMxZGFSVVV6V0RFeFRHVktUVVJvZVhGUmRUaFJNV04wYm5BMFlubHNlVkZLUTNOM0lpd2lkSGx3SWpvaVNrOVRSU0lzSW1WdVl5STZJa0V5TlRaSFEwMGlMQ0poYkdjaU9pSlNVMEV0VDBGRlVDMHlOVFlpZlEuQ2dtcVJFVC1LM0NtTVFPQnRyZ21yT3BXYzdQTGhBSHFUTVc0WGJZeFQ1U2ZNN3I5NFZNU29Ub0l6aGlqMkpwMFRLMmRiVzVFdk8zbWFiOHc1OElrSHR4RF96cWNpR2N0eDJCTXMwUDJnemppT3dVZVdNbWZhUHQtalVxTmlNQjdqcExBN2JSMjZSQUVkQjZGMHRwbU5yNVpkUzJrbzhxZXFlRmp3RDNsbHR3c0RiRkxjLW1zRTExa1RBbHZBVTZwZGJYWjl3dVluOXE4NWl6Ym4ybXYzUExDQV9qY1ZEYlZONUU4UDJNQTdXVndHd0cxeE5HeE5ZR1JQSDNGLVA4QjNDNEVhd0lYcjVmcUdBZUVyYk16Y2x3anUxNXFBVG42U2hsWVVFemhBVXh4RzlMZ0FIRTg2VzREVnk3N2ZlMnBCSElCbHlUcm5QU2JjcE5FZnljdjBRLmpmcXhrcHJ6aFdxbDBwV0YuN1JERndUN0E1S2tIdHcuaXMxZVBENVgycGVMM0tYbWt1RVpBdw.f0es0lbi2SyS6NCLho9B1iiLqTJtAVo5nHVw-xKFylkSgFYgAOkycWNzsdbnfYC0uX3BJwFvQ5Cpk6k1JOzBCGQXPKYxfj3mEN_KuyZwLTvkOs20FdM48CJDTrg8YjqTAgV_8qpck1v7UuqERx5ld6ifqoarfJaLTqRGS0enyF-wG3NnclW5isdsXDUrBAV-YPwsF7yCoyJ40J2N8AflTk69i-UhKnnb11yHUrGY67hmx3Gb60mmG6AC1P8_OhXLXB4gBuihszZSiCrs4qu1jUslvgDfE0kJaCEDyJ1EtfkSp0wMcqpxmnPjhpbCPWgOCq_orn-CiQhn3_QxhyYtXQ"
        val keyName = "src/test/resources/visa/test1.pkcs8"
        val verifierKey = "src/test/resources/visa/test1.pub"
        val decryptorVisa = DecryptorVisa(
            ClassPathKeyLoaderProvider.from(keyName).asVisaPrivateKey(),
            ClassPathKeyLoaderProvider.from(verifierKey).asVisaVerifierKey()
        )
        //when
        val result = decryptorVisa.execute(encryptedAndSignedMessage)
        //then
        Assertions.assertEquals("hola mundo", result)

    }

}