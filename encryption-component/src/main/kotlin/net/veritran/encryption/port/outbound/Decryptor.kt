package net.veritran.encryption.port.outbound

fun interface Decryptor {
    operator fun invoke(encryptedPayload: String): String
}