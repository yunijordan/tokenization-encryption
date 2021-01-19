package net.veritran.encryption.port.driven

import java.security.Key

fun interface Unwrapper {
    operator fun invoke(wrappedMessage: ByteArray): Key
}