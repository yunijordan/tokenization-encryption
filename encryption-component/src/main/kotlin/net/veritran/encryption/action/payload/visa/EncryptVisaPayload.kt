package net.veritran.encryption.action.payload.visa

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.RSASSASigner
import net.veritran.encryption.domain.algorithm.KeyAlgorithms
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class EncryptVisaPayload {

    //TODO: Define jwe and jws headers (alg, enc, typ...)
    fun execute(payload: String, encryptionPublicKey: String, signaturePrivateKey: String): String {
        val jwe =  createJwe(payload, "", encryptionPublicKey)
        return createJws(jwe, "", signaturePrivateKey)
    }

    private fun createJwe(payload: String, header: String, publicKey: String): String {
        val jweHeader: JWEHeader = JWEHeader.parse(header)
        val jweObject = JWEObject(jweHeader, Payload(payload))
        val rsaPublicKey = KeyFactory
            .getInstance(KeyAlgorithms.RSA.value)
            .generatePublic(X509EncodedKeySpec(publicKey.toByteArray())) as RSAPublicKey
        val encryptor = RSAEncrypter(rsaPublicKey)
        jweObject.encrypt(encryptor)
        return jweObject.serialize()
    }

    private fun createJws(jwe: String, header: String, signaturePrivateKey: String): String {
        val jwsHeader: JWSHeader = JWSHeader.parse(header)
        val rsaPrivateKey = KeyFactory
            .getInstance(KeyAlgorithms.RSA.value)
            .generatePrivate(PKCS8EncodedKeySpec(signaturePrivateKey.toByteArray())) as RSAPrivateKey
        val jwsSigner: JWSSigner = RSASSASigner(rsaPrivateKey)
        val jwsObject = JWSObject(jwsHeader, Payload(jwe))
        jwsObject.sign(jwsSigner)
        return jwsObject.serialize()
    }

}