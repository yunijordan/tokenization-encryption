package net.veritran.encryption.port.driven

fun interface Encryptor {
    operator fun invoke(payload: String): String
}