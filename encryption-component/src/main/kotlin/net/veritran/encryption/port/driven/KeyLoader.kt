package net.veritran.encryption.port.driven

import java.security.Key

fun interface KeyLoader {
    fun from(name: String): Key
}