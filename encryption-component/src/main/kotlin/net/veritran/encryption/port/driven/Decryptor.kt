package net.veritran.encryption.port.driven

fun interface Decryptor {
    operator fun invoke(encryptedPayload: String): String
}