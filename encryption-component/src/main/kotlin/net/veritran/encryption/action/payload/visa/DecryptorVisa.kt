package net.veritran.encryption.action.payload.visa

import com.nimbusds.jose.JWEDecrypter
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.RSADecrypter
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.util.Base64URL
import net.veritran.encryption.port.outbound.KeyLoader
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

class DecryptorVisa(
    private val classPathPkcs8RsaPrivateKeyLoader: KeyLoader,
    private val classPathX509PublicKeyLoader: KeyLoader
) {
    val publicKeyName = "src/test/resources/visa/test1.pub"
    val verifier: JWSVerifier = RSASSAVerifier(
        classPathX509PublicKeyLoader.from(publicKeyName) as RSAPublicKey
    )

    fun String.toBase64Url() = Base64URL(this)

    fun execute(encryptedAndSignedMessage: String, keyName: String): String {
        val decrypter: JWEDecrypter = RSADecrypter(
            classPathPkcs8RsaPrivateKeyLoader.from(keyName) as RSAPrivateKey
        )
        val payload = JWSObject.parse(encryptedAndSignedMessage).takeIf { it.verify(verifier) }
            ?.payload
            .toString()

        return JWEObject.parse(payload).also { it.decrypt(decrypter) }.payload.toString()
    }

}
