package net.veritran.encryption.infrastructure.adapter.outbound

import net.veritran.encryption.port.outbound.KeyLoader
import java.io.FileInputStream
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

val classPathPkcs8RsaPrivateKeyLoader = KeyLoader {
    it.let(Paths::get)
        .let(Files::readAllBytes)
        .let(::PKCS8EncodedKeySpec)
        .let(KeyFactory.getInstance("RSA")::generatePrivate)
}

val classPathX509PublicCertLoader = KeyLoader {
    FileInputStream(it)
        .let(CertificateFactory.getInstance("X.509")::generateCertificate).publicKey
}

val classPathX509PublicKeyLoader = KeyLoader {
    it.let(Paths::get)
        .let(Files::readAllBytes)
        .let(::X509EncodedKeySpec)
        .let((KeyFactory.getInstance("RSA")::generatePublic))
}