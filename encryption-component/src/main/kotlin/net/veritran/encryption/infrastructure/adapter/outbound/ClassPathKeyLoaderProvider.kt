package net.veritran.encryption.infrastructure.adapter.outbound

import net.veritran.encryption.action.payload.mastercard.DecryptorMastercard.MastercardPrivateKeyLoader
import net.veritran.encryption.action.payload.mastercard.EncryptorMastercard.MastercardPublicKeyLoader
import net.veritran.encryption.action.payload.visa.DecryptorVisa.VisaPrivateKeyLoader
import net.veritran.encryption.action.payload.visa.DecryptorVisa.VisaVerifierKeyLoader
import net.veritran.encryption.action.payload.visa.EncryptorVisa.VisaPublicKeyLoader
import net.veritran.encryption.action.payload.visa.EncryptorVisa.VisaSignerKeyLoader
import java.io.FileInputStream
import java.nio.file.Files
import java.nio.file.Paths
import java.security.Key
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

typealias ClassPathKeyLoader = (String) -> Key

class ClassPathKeyLoaderProvider private constructor(
    private val path: String
) {

    fun asMastercardPublicKey() = MastercardPublicKeyLoader { x509PublicCertLoader(path) }
    fun asMastercardPrivateKey() = MastercardPrivateKeyLoader { pkcs8RsaPrivateKeyLoader(path) }

    fun asVisaPrivateKey() = VisaPrivateKeyLoader { pkcs8RsaPrivateKeyLoader(path) }
    fun asVisaPublicKey() = VisaPublicKeyLoader { x509PublicKeyLoader(path) }
    fun asVisaVerifierKey() = VisaVerifierKeyLoader { x509PublicKeyLoader(path) }
    fun asVisaSingerKey() = VisaSignerKeyLoader { pkcs8RsaPrivateKeyLoader(path) }

    companion object Factory {
        private val instances: MutableMap<String, ClassPathKeyLoaderProvider> = mutableMapOf()
        fun from(path: String) = instances[path] ?: ClassPathKeyLoaderProvider(path).also { instances[path] = it }
    }

}

private val pkcs8RsaPrivateKeyLoader: ClassPathKeyLoader = {
    Paths.get(it)
        .let(Files::readAllBytes)
        .let(::PKCS8EncodedKeySpec)
        .let(KeyFactory.getInstance("RSA")::generatePrivate)
}

private val x509PublicCertLoader: ClassPathKeyLoader = {
    FileInputStream(it)
        .let(CertificateFactory.getInstance("X.509")::generateCertificate).publicKey
}

private val x509PublicKeyLoader: ClassPathKeyLoader = {
    Paths.get(it)
        .let(Files::readAllBytes)
        .let(::X509EncodedKeySpec)
        .let((KeyFactory.getInstance("RSA")::generatePublic))
}
