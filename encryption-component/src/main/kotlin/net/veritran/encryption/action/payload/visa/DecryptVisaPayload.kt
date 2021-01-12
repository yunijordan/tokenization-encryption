package net.veritran.encryption.action.payload.visa

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier

import net.veritran.encryption.domain.algorithm.KeyAlgorithms
import net.veritran.encryption.domain.error.InvalidJwsException
import net.veritran.encryption.domain.error.InvalidSignatureException
import net.veritran.encryption.infrastructure.Base64Decode

import java.security.KeyFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.X509EncodedKeySpec

class DecryptVisaPayload {

    fun execute(jws: String, key: String): String {
        verifySignature(jws, key)
        val jwsData: JWSData = parseJws(jws)
        return decryptPayload(jwsData.payload())
    }

    private fun verifySignature(jws: String, key: String) {
        val keyFactory: KeyFactory = KeyFactory.getInstance(KeyAlgorithms.RSA.value)
        val publicKey: RSAPublicKey = keyFactory.generatePublic(X509EncodedKeySpec(key.toByteArray())) as RSAPublicKey
        val verifier: JWSVerifier = RSASSAVerifier(publicKey)
        if(!JWSObject.parse(jws).verify(verifier))
            throw InvalidSignatureException("The JWS Signature verify failed")
    }

    private fun parseJws(jws: String): JWSData {
        val jwsComponents = jws.split(".")
        if(jwsComponents.size != 3)
            throw InvalidJwsException("The JWS doesn't contains three parts")
        return JWSData(jwsComponents[0], jwsComponents[1], jwsComponents[2])
    }

    private fun decryptPayload(jws: String): String {
        return "{$jws}"
    }

    class JWSData(
        private val header: String,
        private val payload: String,
        private val signature: String
    ) {

        fun payload() = payload
        fun decode(encodedValue: String) = encodedValue.Base64Decode()

     }

}