package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll
import uk.org.lidalia.encoding.core.EncodedBytes
import uk.org.lidalia.lang.Bytes

import javax.crypto.BadPaddingException
import java.nio.charset.Charset
import java.security.GeneralSecurityException

import static java.nio.charset.StandardCharsets.UTF_8
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64

abstract class CryptoKeyTests extends Specification {

    @Shared Bytes message = Bytes.of(RandomStringUtils.random(15))

    @Shared keyPair = generateKeyPair()
    @Shared encryptKey = keyPair.first
    @Shared decryptKey = keyPair.second
    @Shared otherDecryptKey = generateKeyPair().second

    abstract Tuple2<EncryptKey, DecryptKey> generateKeyPair()
    abstract List<CipherAlgorithm> supportedAlgorithms()
    abstract CipherAlgorithm defaultAlgorithm()

    @Unroll
    def 'can use #algorithm to encrypt and decrypt message'() {

        given:
            def encrypted = encryptKey.encrypt(message, algorithm)

        expect:
            decryptKey.decrypt(encrypted, algorithm) == message

        where:
            algorithm << supportedAlgorithms()
    }

    @Unroll
    def 'decrypting works using overloaded method #method'() {

        given:
            def encrypted = encryptKey.encrypt(message)

        expect:
            doDecrypt(encrypted) == message

        where:
            method                                                             | doDecrypt
            DecryptKey.getMethod('decrypt', EncryptionResult)                  | { EncryptionResult enc -> decryptKey.decrypt(enc) }
            DecryptKey.getMethod('decrypt', Bytes)                             | { EncryptionResult enc -> decryptKey.decrypt(enc.bytes().array()) }
            DecryptKey.getMethod('decrypt', byte[])                            | { EncryptionResult enc -> decryptKey.decrypt(enc.bytes().array()) }
            DecryptKey.getMethod('decrypt', EncodedBytes)                      | { EncryptionResult enc -> decryptKey.decrypt(base64.encode(enc.bytes())) }

            DecryptKey.getMethod('decrypt', EncryptionResult, CipherAlgorithm) | { EncryptionResult enc -> decryptKey.decrypt(enc, defaultAlgorithm()) }
            DecryptKey.getMethod('decrypt', Bytes, CipherAlgorithm)            | { EncryptionResult enc -> decryptKey.decrypt(enc.bytes(), defaultAlgorithm()) }
            DecryptKey.getMethod('decrypt', byte[], CipherAlgorithm)           | { EncryptionResult enc -> decryptKey.decrypt(enc.bytes().array(), defaultAlgorithm()) }
            DecryptKey.getMethod('decrypt', EncodedBytes, CipherAlgorithm)     | { EncryptionResult enc -> decryptKey.decrypt(base64.encode(enc.bytes()), defaultAlgorithm()) }

    }

    @Unroll
    def 'encrypting works using overloaded method #method'() {

        given:
            def encrypted = doEncrypt() as EncryptionResult

        expect:
            decryptKey.decrypt(encrypted) == message

        where:
            method                                                            | doEncrypt
            EncryptKey.getMethod('encrypt', Bytes)                            | { encryptKey.encrypt(message) }
            EncryptKey.getMethod('encrypt', byte[])                           | { encryptKey.encrypt(message.array()) }
            EncryptKey.getMethod('encrypt', String, Charset)                  | { encryptKey.encrypt(message.string(), UTF_8) }
            EncryptKey.getMethod('encrypt', String)                           | { encryptKey.encrypt(message.string()) }

            EncryptKey.getMethod('encrypt', Bytes, CipherAlgorithm)           | { encryptKey.encrypt(message, defaultAlgorithm()) }
            EncryptKey.getMethod('encrypt', byte[], CipherAlgorithm)          | { encryptKey.encrypt(message.array(), defaultAlgorithm()) }
            EncryptKey.getMethod('encrypt', String, Charset, CipherAlgorithm) | { encryptKey.encrypt(message.string(), UTF_8, defaultAlgorithm()) }
            EncryptKey.getMethod('encrypt', String, CipherAlgorithm)          | { encryptKey.encrypt(message.string(), defaultAlgorithm()) }
    }

    def 'throws exception decrypting with wrong key'() {

        given:
            def encrypted = encryptKey.encrypt(message)

        when:
            otherDecryptKey.decrypt(encrypted)

        then:
            def e = thrown(DecryptionFailedException)
            e.message == 'Unable to decrypt data'
            e.cause instanceof BadPaddingException

    }

    def 'throws exception decrypting random data'() {

        when:
            decryptKey.decrypt(randomMessage)

        then:
            def e = thrown(DecryptionFailedException)
            e.message == 'Unable to decrypt data'
            e.cause instanceof GeneralSecurityException

        where:
            randomMessage = Bytes.of(RandomStringUtils.random(32))
    }
}
