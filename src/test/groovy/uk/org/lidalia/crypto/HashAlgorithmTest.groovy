package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll
import uk.org.lidalia.encoding.Bytes
import uk.org.lidalia.encoding.Encoded

import java.nio.charset.Charset

import static java.nio.charset.StandardCharsets.UTF_8
import static uk.org.lidalia.crypto.HashAlgorithm.SHA256

class HashAlgorithmTest extends Specification {

    @Shared toHash = Bytes.of(RandomStringUtils.random(100))
    @Shared anotherValue = Bytes.of(RandomStringUtils.random(100))

    @Unroll
    def 'can hash and verify using algorithm #hashAlgorithm'() {

        when:
            def hash = hashAlgorithm.hash(toHash)

        then:
            hash.matches(toHash)
            !hash.matches(anotherValue)

            if (hash != HashAlgorithm.NONE) {
                hash.bytes().string() != toHash
            }

        where:
            hashAlgorithm << HashAlgorithm.values().toList()
    }

    @Unroll
    def 'hashing works using overloaded method #method'() {

        when:
            def hash = doHash()

        then:
            hash.matches(toHash)
            !hash.matches(anotherValue)
            hash.bytes().string() != toHash

        where:
            method                                           | doHash
            HashAlgorithm.getMethod('hash', Bytes)           | { SHA256.hash(toHash) }
            HashAlgorithm.getMethod('hash', byte[])          | { SHA256.hash(toHash.array()) }
            HashAlgorithm.getMethod('hash', Encoded)         | { SHA256.hash(toHash.encode()) }
            HashAlgorithm.getMethod('hash', String, Charset) | { SHA256.hash(toHash.string(), UTF_8) }
            HashAlgorithm.getMethod('hash', String)          | { SHA256.hash(toHash.string()) }
    }

    @Unroll
    def 'hash matching works using overloaded method #method'() {

        when:
            def hash = SHA256.hash(toHash)

        then:
            matches(hash, toHash)
            !matches(hash, anotherValue)

        where:
            method                                     | matches
            Hash.getMethod('matches', Bytes)           | { Hash theHash, Bytes toMatch -> theHash.matches(toMatch) }
            Hash.getMethod('matches', byte[])          | { Hash theHash, Bytes toMatch -> theHash.matches(toMatch.array()) }
            Hash.getMethod('matches', Encoded)         | { Hash theHash, Bytes toMatch -> theHash.matches(toMatch.encode()) }
            Hash.getMethod('matches', String, Charset) | { Hash theHash, Bytes toMatch -> theHash.matches(toMatch.string(UTF_8)) }
            Hash.getMethod('matches', String)          | { Hash theHash, Bytes toMatch -> theHash.matches(toMatch.string()) }
    }
}
