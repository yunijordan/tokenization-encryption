package net.veritran.encryption.port.inbound

fun interface CipherAction {
    fun execute(payload : String) : String
}