package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll
import uk.org.lidalia.encoding.core.EncodedBytes
import uk.org.lidalia.hash.HashAlgorithm
import uk.org.lidalia.lang.Bytes

import java.nio.charset.Charset

import static java.nio.charset.StandardCharsets.UTF_8
import static uk.org.lidalia.hash.HashAlgorithm.SHA256
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64

abstract class SigningKeyTests extends Specification {

    @Shared keyPair = generateKeyPair()
    @Shared publicKey = keyPair.publicKey()
    @Shared privateKey = keyPair.privateKey()

    @Shared otherPublicKey = generateKeyPair().publicKey()

    @Shared Bytes message = Bytes.of(RandomStringUtils.random(25))

    abstract KeyPair generateKeyPair()
    abstract List<HashAlgorithm> supportedAlgorithms()

    @Unroll
    def 'can use #algorithm to sign and verify message'() {

        given:
            def signature = privateKey.sign(message, algorithm)

        expect:
            publicKey.verify(signature, message)

        where:
            algorithm << supportedAlgorithms()
    }

    @Unroll
    def 'verifying works using overloaded method #method'() {

        given:
            def signature = privateKey.sign(message)
            def notMatchingSignature = privateKey.sign(Bytes.of(RandomStringUtils.random(60)))

        expect:
            doVerify(signature)

        and:
            !doVerify(notMatchingSignature)

        where:
            method                                                                      | doVerify
            PublicKey.getMethod('verify', Signature, Bytes)                             | { Signature sig -> publicKey.verify(sig, message) }
            PublicKey.getMethod('verify', Signature, byte[])                            | { Signature sig -> publicKey.verify(sig, message.array()) }
            PublicKey.getMethod('verify', Signature, EncodedBytes)                      | { Signature sig -> publicKey.verify(sig, base64.encode(message)) }
            PublicKey.getMethod('verify', Signature, String, Charset)                   | { Signature sig -> publicKey.verify(sig, message.string(), UTF_8) }
            PublicKey.getMethod('verify', Signature, String)                            | { Signature sig -> publicKey.verify(sig, message.string()) }

            PublicKey.getMethod('verify', Bytes, HashAlgorithm, Bytes)                  | { Signature sig -> publicKey.verify(sig.bytes(), SHA256, message) }
            PublicKey.getMethod('verify', Bytes, HashAlgorithm, byte[])                 | { Signature sig -> publicKey.verify(sig.bytes(), SHA256, message.array()) }
            PublicKey.getMethod('verify', Bytes, HashAlgorithm, EncodedBytes)           | { Signature sig -> publicKey.verify(sig.bytes(), SHA256, base64.encode(message)) }
            PublicKey.getMethod('verify', Bytes, HashAlgorithm, String, Charset)        | { Signature sig -> publicKey.verify(sig.bytes(), SHA256, message.string(), UTF_8) }
            PublicKey.getMethod('verify', Bytes, HashAlgorithm, String)                 | { Signature sig -> publicKey.verify(sig.bytes(), SHA256, message.string()) }

            PublicKey.getMethod('verify', byte[], HashAlgorithm, Bytes)                 | { Signature sig -> publicKey.verify(sig.bytes().array(), SHA256, message) }
            PublicKey.getMethod('verify', byte[], HashAlgorithm, byte[])                | { Signature sig -> publicKey.verify(sig.bytes().array(), SHA256, message.array()) }
            PublicKey.getMethod('verify', byte[], HashAlgorithm, EncodedBytes)          | { Signature sig -> publicKey.verify(sig.bytes().array(), SHA256, base64.encode(message)) }
            PublicKey.getMethod('verify', byte[], HashAlgorithm, String, Charset)       | { Signature sig -> publicKey.verify(sig.bytes().array(), SHA256, message.string(), UTF_8) }
            PublicKey.getMethod('verify', byte[], HashAlgorithm, String)                | { Signature sig -> publicKey.verify(sig.bytes().array(), SHA256, message.string()) }

            PublicKey.getMethod('verify', EncodedBytes, HashAlgorithm, Bytes)           | { Signature sig -> publicKey.verify(base64.encode(sig.bytes()), SHA256, message) }
            PublicKey.getMethod('verify', EncodedBytes, HashAlgorithm, byte[])          | { Signature sig -> publicKey.verify(base64.encode(sig.bytes()), SHA256, message.array()) }
            PublicKey.getMethod('verify', EncodedBytes, HashAlgorithm, EncodedBytes)    | { Signature sig -> publicKey.verify(base64.encode(sig.bytes()), SHA256, base64.encode(message)) }
            PublicKey.getMethod('verify', EncodedBytes, HashAlgorithm, String, Charset) | { Signature sig -> publicKey.verify(base64.encode(sig.bytes()), SHA256, message.string(), UTF_8) }
            PublicKey.getMethod('verify', EncodedBytes, HashAlgorithm, String)          | { Signature sig -> publicKey.verify(base64.encode(sig.bytes()), SHA256, message.string()) }

    }

    @Unroll
    def 'signing works using overloaded method #method'() {

        given:
            def signature = doSign() as Signature

        expect:
            publicKey.verify(signature, message)

        where:
            method                                                       | doSign
            PrivateKey.getMethod('sign', Bytes, HashAlgorithm)           | { privateKey.sign(message, SHA256) }
            PrivateKey.getMethod('sign', byte[], HashAlgorithm)          | { privateKey.sign(message.array(), SHA256) }
            PrivateKey.getMethod('sign', EncodedBytes, HashAlgorithm)    | { privateKey.sign(base64.encode(message), SHA256) }
            PrivateKey.getMethod('sign', String, Charset, HashAlgorithm) | { privateKey.sign(message.string(), UTF_8, SHA256) }
            PrivateKey.getMethod('sign', String, HashAlgorithm)          | { privateKey.sign(message.string(), SHA256) }

            PrivateKey.getMethod('sign', Bytes)                          | { privateKey.sign(message) }
            PrivateKey.getMethod('sign', byte[])                         | { privateKey.sign(message.array()) }
            PrivateKey.getMethod('sign', EncodedBytes)                   | { privateKey.sign(base64.encode(message)) }
            PrivateKey.getMethod('sign', String, Charset)                | { privateKey.sign(message.string(), UTF_8) }
            PrivateKey.getMethod('sign', String)                         | { privateKey.sign(message.string()) }
    }

    def 'does not verify with different key'() {

        when:
            def signature = privateKey.sign(message)

        then:
            !otherPublicKey.verify(signature, message)

    }

    def 'does not verify tampered data'() {

        when:
            def signature = privateKey.sign(message)

        then:
            !publicKey.verify(signature, tamperedMessage)

        where:
            tamperedMessage = Bytes.of(RandomStringUtils.random(60))
    }
}
