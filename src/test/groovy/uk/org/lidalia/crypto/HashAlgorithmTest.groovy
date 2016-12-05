package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Specification
import spock.lang.Unroll

class HashAlgorithmTest extends Specification {

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
            toHash = RandomStringUtils.random(100);
            anotherValue = RandomStringUtils.random(100);
            hashAlgorithm << HashAlgorithm.values().toList()
    }
}
