package net.veritran.encryption.action.payload.visa

import com.nimbusds.jose.*
import com.nimbusds.jose.JOSEObjectType.JOSE
import com.nimbusds.jose.crypto.RSAEncrypter
import com.nimbusds.jose.crypto.RSASSASigner
import net.veritran.encryption.port.inbound.CipherAction
import net.veritran.encryption.port.outbound.keys.CipherKeyLoader
import java.security.PrivateKey
import java.security.interfaces.RSAPublicKey
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class EncryptorVisa(
    private val publicVisaKeyLoader: VisaPublicKeyLoader,
    private val privateSignatureKeyLoader: VisaSignerKeyLoader
): CipherAction {

    private val kid = "7ZEIVC16DGRDQKWZEE3X11LeJMDhyqQu8Q1ctnp4bylyQJCsw"
    private val secretKey: SecretKey = KeyGenerator.getInstance("AES").also { it.init(256) }.generateKey()

    override fun execute(message: String): String {
        val jweEncrypter: JWEEncrypter = RSAEncrypter(
            publicVisaKeyLoader.get() as RSAPublicKey,
            secretKey
        )
        val jweHeader = JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
            .keyID(kid).type(JOSE)
            //.customParam("ait", now())
            .build()
        val jweEncryptResult = JWEObject(
            jweHeader,
            Payload(message)
        ).also { it.encrypt(jweEncrypter) }
            .serialize()

        val signer: JWSSigner = RSASSASigner(privateSignatureKeyLoader.get() as PrivateKey)
        val jwsHeader = JWSHeader.Builder(JWSAlgorithm.PS256).keyID(kid).type(JOSE)
            .contentType("JWE").build()
        return JWSObject(jwsHeader, Payload(jweEncryptResult)).also { it.sign(signer) }.serialize()
    }

    fun interface VisaPublicKeyLoader : CipherKeyLoader
    fun interface VisaSignerKeyLoader : CipherKeyLoader

}
