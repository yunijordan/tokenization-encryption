package net.veritran.encryption.infrastructure.adapter.driven

import net.veritran.encryption.port.driven.KeyLoader
import java.io.FileInputStream
import java.nio.file.Files
import java.nio.file.Paths
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec

val classPathPkcs8RsaLoader = KeyLoader {
    it.let(Paths::get)
        .let(Files::readAllBytes)
        .let(::PKCS8EncodedKeySpec)
        .let(KeyFactory.getInstance("RSA")::generatePrivate)
}

val classPathX509Loader = KeyLoader {
    FileInputStream(it)
        .let(CertificateFactory.getInstance("X.509")::generateCertificate).publicKey
}