package action

import net.veritran.encryption.infrastructure.EncryptUtils
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers
import org.jose4j.keys.AesKey
import org.jose4j.lang.ByteUtil
import java.security.Key
import java.util.*


object EncryptFixture {
    const val aMessage = "a value"
    const val aCipherTransformation = "RSA/ECB/PKCS1Padding"
    const val aCipherAlgorithm = "RSA"
    const val aKeyAlgorithm = "RSA"
    const val aTransformation = "RSA"
    const val aHashAlgorithm = "SHA-256"
    const val anAlgorithmIdentifier = KeyManagementAlgorithmIdentifiers.RSA_OAEP_256

    const val anEncryptedMessage =
        "V/n5n2+hTtXQdewKVEbHA7fZp62NoHWTQP8g6UqUqiQw1D2n1girmHw9sl4tinGEVFLk0kdn+3SG8sMEcrLL03sQ5upBECarwBD6QEiBqkHaNNy639j5/iCXiIwHIaLShGFExdtKsNyBMas7zsscFQR1M4y1nS68NDjxecb18ZY="
    val aHashedMessage: ByteArray = Base64.getDecoder()
        .decode("c2QyCMkJ7ESuACFkduwfibNKl7WCqNisuvZXwcjExZI3sWLyuq0gR+6l0ixWVVLrlP8BUd1vsFA20GbwZDiJGuw7vSizHSE7Y8/IdUqelAHr+Sq6xRoOv80nhl1OkYGAbpgfw8zsXWlbXOUNB2BJYO2Nv7zMNtZZv6WBI84VPTM=".toByteArray())

    const val aPublicKey =
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCVL7kd/jl7uBLxTETUkRdGJIkDDaCQxX4TNEvxoAWbiJDQvgnmilJJCiultCNYBssvGnz7BbfxxlJnLqz71yIkkq7q0bwYhZyw4bngXl72RYnY+OQdfC6edizilv65ClSNKsD8rJcWIQuukItSUgOAGkGG+yZznyMwOe7Zou01EwIDAQAB"
    const val aPrivateKey =
        "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJUvuR3+OXu4EvFMRNSRF0YkiQMNoJDFfhM0S/GgBZuIkNC+CeaKUkkKK6W0I1gGyy8afPsFt/HGUmcurPvXIiSSrurRvBiFnLDhueBeXvZFidj45B18Lp52LOKW/rkKVI0qwPyslxYhC66Qi1JSA4AaQYb7JnOfIzA57tmi7TUTAgMBAAECgYEAg5HRCriYbZoLaq8+zNEg24WBKCYugz8JT1qB15ivGVo5jT7scFtw8mV71OmnegyTyPjtXFzQuvOS3Nj3SiuTOZem25o1ME8MgHHTilvhHO26+70N51nwj5aTOLPymJMbhsI8lQzcYtA+OYC2UXwGJgMV6pae+57db6zUJf/IFnECQQD3ZAMDLDxBflPK9knNlalae1c9FmJB2QyT5joaFdkm0y+y1322BK04ytmbAT4xc9rrY8qiqdYUftgggcvwP9KfAkEAmmDQ0sivXJK69dibwBV4eK1Jqxtowao9q6j/tjfPTpgz59mpBEK9CrnG+fOgRCNi2Hqev0p1NbPcmkgXqfydDQJAMQQe2K0WDz/xaEBeJR6nHGddxJu/wh44MMGn920mxluHkt7BaKQKkjsW3HBlmzTCRmtSReJyqULsnZw6BRMQLwJAF9CjpkCrPL6t9MsLi+BEC2nAGZNK38Vhah/SAswtQNSd/UBIoI2jGAp8tYZtzNUgpICWCLB10GkEuRAyBlkf6QJBAPJkJM3I+a3OyBRUAfULR+xAV1RB3yU6kzIzub1ML/UR3lriQ84glD/1VjOmA4n09JMdLPEfXNLKPbuLrG7vf0E="

    const val aPublicKey_2048 =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmoi//+BluKTjEMODw5d2UBYgZ23get9b2OMQCk8Xw6/WYA5xNS+YapaWG86DT5rERlJly6BdGr2xjAx7qiXb71huXZsQUwnDPQAmgGzwPTyJ/0vzyyfc1cp2/mlr/IQ/6FmdNjv7dK0lHbGcU5lxYIAThB6xaekLvJiQeKU0yjUlIb0xWTSFTv4DgXxBkj6V+RlrzFIzMT//jCdxHEILm+PbjrFGREFPuCwENBtsIMMvqc+Ip7HD+OHKKXpyn+GCH/jWtw0ZiHI2xZNIRv7ZnKCE/V4TuZgon8QELQwhhdwBQX9ZDlEpIUYFb8812A3XEbG05tX2Qd3+2uvKsxjrRwIDAQAB"
    const val aPrivateKey_2048 =
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCaiL//4GW4pOMQw4PDl3ZQFiBnbeB631vY4xAKTxfDr9ZgDnE1L5hqlpYbzoNPmsRGUmXLoF0avbGMDHuqJdvvWG5dmxBTCcM9ACaAbPA9PIn/S/PLJ9zVynb+aWv8hD/oWZ02O/t0rSUdsZxTmXFggBOEHrFp6Qu8mJB4pTTKNSUhvTFZNIVO/gOBfEGSPpX5GWvMUjMxP/+MJ3EcQgub49uOsUZEQU+4LAQ0G2wgwy+pz4inscP44copenKf4YIf+Na3DRmIcjbFk0hG/tmcoIT9XhO5mCifxAQtDCGF3AFBf1kOUSkhRgVvzzXYDdcRsbTm1fZB3f7a68qzGOtHAgMBAAECggEBAISkjpEWTpm/xjs0ZtwzHNW/OE8vC/jL0a2HsNP4ccCBJLRMkTWCxgPvf6cciq+Ae6qUvVWcL25tloFMkbVJS8/Uit8D424zOgcZIvMnDsqxNQ4SZo9hhvdnEt5rJMqZxbUtfnj34W2T1QD42+MSGTQomxfTtJrg8zcNiSxVOcu5nX3NmpJG4JP6u2rRnZ0VnMOORrQpFlxN0F+SiMpxSoxYqDNEd4rgODN7kocbp7RmBg8QTvrScmjykd7zYrZPhh73SS81UFzv1/OsohfCJocalPxZhpmBR90nwtivJHfOm8QqWnqLoXKuqVL9+wRyxmw61cdRis0H8ddazt4drtECgYEA2UYosCIVqryQkoPWANhDoRD4V7MSUNPRr+smeg7sjjUgoVXzWqU3t4fbd51AvXWg+iqlt9UjkvDSTUlAis+YzveVYswUZPCLHDVFg6u7q3KN5PpwCVpf14WcTBlAqLmnd9bnUOqbmbwonHIjZR+zONHYi1WC2ouy8qNj6QYJ3XkCgYEAthPg4oNvwVe19lL/CvkWDsqUir4JleBx71zWNBRPX59HZn4quTIw3j3ZluTWSqPhetoAZedegahNHKeNlXi5ZUR2AF+k94Rtu4xdV5WIIj+/f5wM80MzafGBAvpg1dFR7srk7e+g6tyIohLzGsiXqNgDtoQ3eGRYPjPJegxsnr8CgYEAtXZaHxiofet011lST2xPt2Kj9yLw5h6ynzlG7mQuf2qxsO1HDOq2CQtnaZQlcNagNq+NrmZNirik+7V1OTm+xwSSeGw3kEIx/MIlJ54zZDKNfbMIBVe8ehT1/7yLex9rVbRfhv4aLKCwTlEpbJi4J3ljYKNvYTWRpAKAPCs17AkCgYACOPvlx/T1RzzRZPH4EFJUm+R0TR2Q1syNP3Td7eGKKUeV2LRszlAKZnbhgKmc/6Mg/MhEdi6RJpzKXME9sduRgORv3LsGyncMcwowp4Kh6GVOCXme/pMCGBCbGLNV6Ng3MgLZZLNyKn8Ae3q8OPag+QISmEqVDaSGHdu3wa8RwQKBgAshtFTYMtjakFYaHMTG48JJaFhT0Iqt2Z8ttnFEwIrkTch2Ap40YtJyRVhkoiKgcHCW4aiwjuvuDtBu63UwLP/WXwSspFbBr/AWmGoDmz2Av9qE3Ocf8FD3gfQ3cawTP9cuSduGDn3XoymMHFVzfN0ndj48EN66TUZPsGtTK4I3"

    val jwePrivateKey = EncryptUtils.getPrivateKey(aPrivateKey_2048, aCipherAlgorithm)

    val symmetricKey: Key = AesKey(ByteUtil.randomBytes(16))
    val aSymmetricKey: String = Base64.getEncoder().encodeToString(symmetricKey.encoded)
    const val anEncryptedJwe =
        "eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.mJd04IZX12ygLvft5VMeQCHQ2kRJs9XFg1lCmdmwmvKRLhPWiv0gMHFwFF2NV_DjoEYXMZtDsrcy5J48VqlIWCiGRD5uNT8OX5jn_KUU3Znfr3H6sMovDUu7kQF4OPhdS-a-QyxjK6enkm0n_AA-lREqTdpuMEz78TXhbpfcfroRwMY6KjCWWMKXMxYGTt1f2bHQoUdrVISJfczgMPbxdZb20kdYRfkaQlZwwNfvJHsmZ6mQA3Na0emGMxvpYAVEeZ3s_xszv3ag4aVar0mDJW5cSucSaLgFLzaVSjiBdNmrU2AFA1sHlcPsgD4QByCtJbe-vDZ4D2SQ-OkaNfBdSw.ywpGLAzm-aM7eFzgVtPdbA.-LXw_5ZqKavkhY6CKg-LM2gGdhzp1chEnc0prOsn8S-DCVROr6Uy3pi89riQyPcM.ZOVYWNpKU1-_ra33f0FmZQ"
}
