package action.payload.itsp

import net.veritran.encryption.action.payload.itsp.DecryptorItsp
import net.veritran.encryption.infrastructure.adapter.outbound.ClassPathKeyLoaderProvider
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

class DecryptorItspTest {

    @Test
    fun `decrypt itsp payload using classpath key loader`() {
        val expected = "{\n \"param1\": \"foo\",\n \"param2\": \"bar\"\n }"
        val keyFilePath = "src/test/resources/keys/test_key_pkcs8-2048.der"
        val publicItspKeyLoader = ClassPathKeyLoaderProvider.from(keyFilePath).asItspPrivateKey()
        val decryptorItsp = DecryptorItsp(publicItspKeyLoader)
        val payload = "eyJlbmNyeXB0ZWREYXRhIiA6ICJhNzM5OTdhZTc1MGUzMmI3OTViZDQ0NDQ4MDc4YWY4MTM2ODg1ZTg1NWZkMzU0MGJmYmQ3NzFiNDI2NTlmZmI4YWUyZmJmNTc5Nzg3ZmRkMWE2MzRiM2E2MjMzNTRhNDUiLCAiZW5jcnlwdGVkS2V5IiA6ICJjMzg4M2RkY2Q0NDcwZDIzNGQxOGUxZWUwZGM3MzlkOTdkYmM0YjkxOWZmM2FhMjliMGE5MjlmMmE1ZjkyMjFmOTM0ZTBkNTQ1YWVhZDY2NzVjOWNhZWFkMGM5MzZmYjJlOWFjMmRhMjBkNmM2YjM1Njg5MTkyMDg2NTY2NjMxNzE5OTcxZWZiMTFjMWZmMzQwZGRkOTVlNTZlYzFkZWExM2QzMjkwZTZmNTZjMDMwZDcwZGY0MmQ0ZjJlMDBjMjhiMzYzZTU0MTQ2Mzk5MmVjYmFiYTdhMTg4NTk1ZjViNGRlOGMyOGY1NjFjYjI1ODFlOGE4MmI3NTNiNmQ5ZWNmMzA3Y2Q0MTdiMGYxZDgzYjM3MjFkM2ZlM2YwN2NmNTlkZTgwMzg2ZGMxYTUwZTIyNDQwODRmYzI1ZjkzN2FiZDdlMTYwMmNmZTliMjg1NTRiYmIxZWNlMGIyNmIzMDFlNjFmNTVmNWEwZGQwMTEzZTQ2YTcxMTQxMWMxYzk0YjExYTQyZGNhYmZhYTU1ODg1ZTExYWFhNzNiZjZjNWM3ZjNmZTYyMWM3ZmUwNzllY2E3ZTNmNmY2YmE2N2E2OTM3MmI3ZDUwZDQ0ZThmYmM4NGU0ODdmZDc4MmM4OWZiMDliNmVlZjliYzZmZWI3YjE1ODg1YmVjMTFhMzJhM2FlYSIsICJpdiIgOiAiZDgzMjA2MGE4NGQxMjBkYzI3OThkYTU1ZTE2ZmYxMWIiLCAib2FlcEhhc2hpbmdBbGdvcml0aG0iIDogIlNIQS0yNTYiLCAicHVibGljS2V5RmluZ2VycHJpbnQiIDogIiJ9"

        val result = decryptorItsp.execute(payload)

        Assertions.assertEquals(expected, result)
    }
}