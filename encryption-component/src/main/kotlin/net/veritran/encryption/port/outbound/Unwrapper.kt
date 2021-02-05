package net.veritran.encryption.port.outbound

import java.security.Key

fun interface Unwrapper {
    operator fun invoke(wrappedMessage: ByteArray): Key
}