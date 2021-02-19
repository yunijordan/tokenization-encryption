package net.veritran.encryption.action.payload.visa

import com.nimbusds.jose.JWEDecrypter
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.crypto.RSASSAVerifier
import net.veritran.encryption.port.inbound.CipherAction
import net.veritran.encryption.port.outbound.keys.CipherKeyLoader
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class DecryptorVisa(
    private val visaPrivateKeyLoader: VisaPrivateKeyLoader,
    private val visaVerifierKeyLoader: VisaVerifierKeyLoader
) : CipherAction {
    private val verifier: JWSVerifier = RSASSAVerifier(
        visaVerifierKeyLoader.get() as RSAPublicKey
    )

    override fun execute(encryptedAndSignedMessage: String): String {
        val decrypter: JWEDecrypter = RSADecrypter(
            visaPrivateKeyLoader.get() as RSAPrivateKey
        )
        val payload = JWSObject.parse(encryptedAndSignedMessage).takeIf { it.verify(verifier) }
            ?.payload
            .toString()

        return JWEObject.parse(payload).also { it.decrypt(decrypter) }.payload.toString()
    }

    fun interface VisaPrivateKeyLoader : CipherKeyLoader
    fun interface VisaVerifierKeyLoader : CipherKeyLoader

}
