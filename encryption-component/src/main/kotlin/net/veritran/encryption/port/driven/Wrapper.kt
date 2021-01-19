package net.veritran.encryption.port.driven

import java.security.Key

fun interface Wrapper {
    operator fun invoke(key: Key): ByteArray
}