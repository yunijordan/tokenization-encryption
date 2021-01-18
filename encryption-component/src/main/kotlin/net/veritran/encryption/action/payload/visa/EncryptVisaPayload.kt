package net.veritran.encryption.action.payload.visa

import net.veritran.encryption.domain.jwt.JWE

class EncryptVisaPayload {

    fun execute(
            payload: String,
            encryptionPublicKey: String,
            signaturePrivateKey: String,
            jweHeader: String,
            jwsHeader: String
    ): String {
        val jwe = JWE(payload)
        jwe.create(jweHeader, encryptionPublicKey)
        return jwe.sign(jwsHeader, signaturePrivateKey)
    }


}