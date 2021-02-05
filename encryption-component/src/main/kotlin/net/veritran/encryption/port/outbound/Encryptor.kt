package net.veritran.encryption.port.outbound

fun interface Encryptor {
    operator fun invoke(payload: String): String
}