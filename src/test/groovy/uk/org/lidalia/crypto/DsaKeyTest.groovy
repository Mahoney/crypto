package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Specification
import spock.lang.Unroll

import static uk.org.lidalia.crypto.HashAlgorithm.SHA1
import static uk.org.lidalia.crypto.HashAlgorithm.SHA224
import static uk.org.lidalia.crypto.HashAlgorithm.SHA256
import static uk.org.lidalia.crypto.dsa.Dsa.DSA

class DsaKeyTest extends Specification {

    @Unroll
    def 'can sign and verify using #algorithm'() {

        given:
            def keyPair = DSA.generateKeyPair(1024)

        when:
            def signature = keyPair.privateKey().sign(message, algorithm)

        then:
            keyPair.publicKey().verify(signature, message)

        where:
            message = RandomStringUtils.random(60)
            algorithm << [SHA1, SHA224, SHA256]
    }
}
