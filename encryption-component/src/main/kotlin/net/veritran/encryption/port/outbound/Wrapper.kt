package net.veritran.encryption.port.outbound

import java.security.Key

fun interface Wrapper {
    operator fun invoke(key: Key): ByteArray
}