package net.veritran.encryption.domain.jwt

import net.veritran.encryption.domain.algorithm.KeyAlgorithms

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.RSASSASigner

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey

import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class JWE(val payload: String) {

    private lateinit var value: String
    
    fun create(header: String, publicKey: String) {
        val jweObject = JWEObject(JWEHeader.parse(header), Payload(payload))
        val encryptor = RSAEncrypter(generatePublicKey(publicKey) as RSAPublicKey)
        jweObject.encrypt(encryptor)
        this.value = jweObject.serialize()
    }

    fun sign(header: String, privateKey: String): String {
        val signer = RSASSASigner(generatePrivateKey(privateKey) as RSAPrivateKey)
        val jwsObject = JWSObject(JWSHeader.parse(header), Payload(value))
        jwsObject.sign(signer)
        return jwsObject.serialize()
    }

    private fun generatePublicKey(publicKey: String): PublicKey =
        KeyFactory.getInstance(KeyAlgorithms.RSA.value).generatePublic(X509EncodedKeySpec(publicKey.toByteArray()))

    private fun generatePrivateKey(privateKey: String): PrivateKey =
        KeyFactory.getInstance(KeyAlgorithms.RSA.value).generatePrivate(PKCS8EncodedKeySpec(privateKey.toByteArray()))

}