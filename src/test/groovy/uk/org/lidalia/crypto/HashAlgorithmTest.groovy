package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll
import uk.org.lidalia.encoding.Bytes
import uk.org.lidalia.encoding.EncodedBytes

import java.nio.charset.Charset

import static java.nio.charset.StandardCharsets.UTF_8
import static uk.org.lidalia.crypto.HashAlgorithm.SHA256

class HashAlgorithmTest extends Specification {

    @Shared toHash = Bytes.of(RandomStringUtils.random(100))
    @Shared anotherValue = Bytes.of(RandomStringUtils.random(100))

    @Unroll
    def 'can hash and verify using algorithm #hashAlgorithm'() {

        given:
            def hash = hashAlgorithm.hash(toHash)

        expect:
            hash.matches(toHash)
            !hash.matches(anotherValue)
            hash.algorithm() == hashAlgorithm

            if (hash != HashAlgorithm.NONE) {
                hash.bytes().string() != toHash
            }

        where:
            hashAlgorithm << HashAlgorithm.values().toList()
    }

    @Unroll
    def 'base64 encoded hash of #message hashed with #hashAlgorithm is #hexHash'() {

        given:
            def hash = hashAlgorithm.hash(message)

        expect:
            hash.toString() == hexHash

        where:
            message = 'Hello World'
            hashAlgorithm << HashAlgorithm.values().toList()
            hexHash << [
                    '48656c6c6f20576f726c64',
                    '27454d000b8f9aaa97da6de8b394d986',
                    'b10a8db164e0754105b7a99be72e3fe5',
                    '0a4d55a8d778e5022fab701977c5d840bbc486d0',
                    'c4890faffdb0105d991a461e668e276685401b02eab1ef4372795047',
                    'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
                    '99514329186b2f6ae4a1329e7ee6c610a729636335174ac6b740f9028396fcc803d0e93863a7c3d90f86beee782f4f3f',
                    '2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b',
            ]
    }

    @Unroll
    def 'hashing works using overloaded method #method'() {

        given:
            def hash = doHash()

        expect:
            hash.matches(toHash)
            !hash.matches(anotherValue)

        where:
            method                                           | doHash
            HashAlgorithm.getMethod('hash', Bytes)           | { SHA256.hash(toHash) }
            HashAlgorithm.getMethod('hash', byte[])          | { SHA256.hash(toHash.array()) }
            HashAlgorithm.getMethod('hash', EncodedBytes)    | { SHA256.hash(toHash.encode()) }
            HashAlgorithm.getMethod('hash', String, Charset) | { SHA256.hash(toHash.string(), UTF_8) }
            HashAlgorithm.getMethod('hash', String)          | { SHA256.hash(toHash.string()) }
    }

    @Unroll
    def 'hash matching works using overloaded method #method'() {

        given:
            def hash = SHA256.hash(toHash)

        expect:
            matches(hash, toHash)
            !matches(hash, anotherValue)

        where:
            method                                     | matches
            Hash.getMethod('matches', Bytes)           | { Hash theHash, Bytes toMatch -> theHash.matches(toMatch) }
            Hash.getMethod('matches', byte[])          | { Hash theHash, Bytes toMatch -> theHash.matches(toMatch.array()) }
            Hash.getMethod('matches', EncodedBytes)    | { Hash theHash, Bytes toMatch -> theHash.matches(toMatch.encode()) }
            Hash.getMethod('matches', String, Charset) | { Hash theHash, Bytes toMatch -> theHash.matches(toMatch.string(UTF_8), UTF_8) }
            Hash.getMethod('matches', String)          | { Hash theHash, Bytes toMatch -> theHash.matches(toMatch.string()) }
    }
}
