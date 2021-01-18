package utils

object VisaFixture {

    val decryptedPayloadExpected = get_decrypted_payload()

    const val encryptedJwsExpected = ""
    const val aValidJws = ""

    const val aSignaturePublicKey = ""
    const val aDecryptionPrivateKey = ""
    const val aEncryptionPublicKey = ""
    const val aSignaturePrivateKey = ""

    const val aJwsHeader = "{\"alg\":\"RSA-OAEP-256\",\"kid\":\"\",\"typ\":\"JOSE\",\"enc\":\"A256GCM\",\"iat\":\"1429837145\"}"
    const val aJweHeader = "{\"alg\":\"PS256\",\"kid\":\"\",\"typ\":\"JOSE\"}"

    val aDecryptedPayload = get_decrypted_payload()

    private fun get_decrypted_payload(): String = "{}"

}