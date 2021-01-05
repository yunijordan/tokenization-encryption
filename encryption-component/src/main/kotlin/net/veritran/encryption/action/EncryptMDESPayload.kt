package net.veritran.encryption.action

import net.veritran.encryption.domain.encoding.Encryptor
import net.veritran.encryption.domain.encoding.EncryptorSha256
import net.veritran.encryption.domain.encoding.UnWrapper
import net.veritran.encryption.domain.encoding.UnWrapperOaepWithMgf1WhichUsesSha256MD
import java.security.KeyFactory
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec

class EncryptMDESPayload(
    private val payload: String,
    private val publicKey: String,
    private val tspKey: ByteArray
) {

    var vector = ByteArray(16)
        .also(SecureRandom.getInstance("SHA1PRNG")::nextBytes)

    private val unWrapper: UnWrapper = PKCS8EncodedKeySpec(tspKey)
        .let(KeyFactory.getInstance("RSA")::generatePrivate)
        .let(::UnWrapperOaepWithMgf1WhichUsesSha256MD)

    private val encryptor: Encryptor = EncryptorSha256(publicKey, unWrapper, vector)

    fun execute() = encryptor use payload

}