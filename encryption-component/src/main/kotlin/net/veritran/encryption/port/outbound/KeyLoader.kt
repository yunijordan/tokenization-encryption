package net.veritran.encryption.port.outbound

import java.security.Key

fun interface KeyLoader {
    fun from(name: String): Key
}