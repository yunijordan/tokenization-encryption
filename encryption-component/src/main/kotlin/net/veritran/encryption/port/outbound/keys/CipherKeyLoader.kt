package net.veritran.encryption.port.outbound.keys

import java.security.Key

fun interface CipherKeyLoader {
    fun get(): Key
}