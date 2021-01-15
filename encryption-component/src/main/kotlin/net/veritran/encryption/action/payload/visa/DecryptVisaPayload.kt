package net.veritran.encryption.action.payload.visa

import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.crypto.RSASSAVerifier

import net.veritran.encryption.domain.algorithm.KeyAlgorithms
import net.veritran.encryption.domain.error.InvalidJwsException
import net.veritran.encryption.domain.error.InvalidSignatureException
import net.veritran.encryption.infrastructure.base64Decode

import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

class DecryptVisaPayload {

    fun execute(jws: String, signaturePublicKey: String, decryptionPrivateKey: String): String {
        verifySignature(jws, signaturePublicKey)
        val jwsData: JWSData = parseJws(jws)
        return decryptPayload(jwsData.payload(), decryptionPrivateKey.toByteArray())
    }

    private fun verifySignature(jws: String, signaturePublicKey: String) {
        val keyFactory: KeyFactory = KeyFactory.getInstance(KeyAlgorithms.RSA.value)
        val rsaPublicKey: RSAPublicKey = keyFactory
                .generatePublic(X509EncodedKeySpec(signaturePublicKey.toByteArray())) as RSAPublicKey
        val verifier: JWSVerifier = RSASSAVerifier(rsaPublicKey)
        if (!JWSObject.parse(jws).verify(verifier))
            throw InvalidSignatureException("The JWS Signature verify failed")
    }

    private fun decryptPayload(jwe: String, decryptionPrivateKey: ByteArray): String {
        val jweObject = JWEObject.parse(jwe)
        val rsaPrivateKey = KeyFactory
            .getInstance(KeyAlgorithms.RSA.value)
            .generatePrivate(PKCS8EncodedKeySpec(decryptionPrivateKey))
        val decryptor = RSADecrypter(rsaPrivateKey)
        jweObject.decrypt(decryptor)
        return jweObject.payload.toString()
    }

    private fun parseJws(jws: String): JWSData {
        val jwsComponents = jws.split(".")
        if (jwsComponents.size != 3)
            throw InvalidJwsException("The JWS doesn't contains three parts")
        return JWSData(jwsComponents[1])
    }

    data class JWSData(private val payload: String) {
        fun payload() = String(payload.base64Decode())
    }

}

