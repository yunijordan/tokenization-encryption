package net.veritran.encryption.domain.jwt

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.RSASSASigner
import net.veritran.encryption.domain.algorithm.KeyAlgorithms
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class JWE(val payload: String) {

    private lateinit var value: String
    
    fun create(header: String, publicKey: String) {
        val jweHeader: JWEHeader = JWEHeader.parse(header)
        val jweObject = JWEObject(jweHeader, Payload(payload))
        val rsaPublicKey = KeyFactory
                .getInstance(KeyAlgorithms.RSA.value)
                .generatePublic(X509EncodedKeySpec(publicKey.toByteArray())) as RSAPublicKey
        val encryptor = RSAEncrypter(rsaPublicKey)
        jweObject.encrypt(encryptor)
        value = jweObject.serialize()
    }

    fun sign(header: String, signaturePrivateKey: String): String {
        val jwsHeader: JWSHeader = JWSHeader.parse(header)
        val rsaPrivateKey = KeyFactory
                .getInstance(KeyAlgorithms.RSA.value)
                .generatePrivate(PKCS8EncodedKeySpec(signaturePrivateKey.toByteArray())) as RSAPrivateKey
        val jwsSigner: JWSSigner = RSASSASigner(rsaPrivateKey)
        val jwsObject = JWSObject(jwsHeader, Payload(value))
        jwsObject.sign(jwsSigner)
        return jwsObject.serialize()
    }

}