package net.veritran.encryption.domain.mastercard

data class EncryptedMastercardPayload(
    val publicKeyFingerprint: String = "",
    val encryptedKey: String = "",
    val oaepHashingAlgorithm: String = "SHA-256",
    val iv: String = "",
    val encryptedData: String = "",
)