package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll
import uk.org.lidalia.crypto.rsa.Rsa
import uk.org.lidalia.encoding.Bytes

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

abstract class AsymmetricKeyTests extends Specification {

    @Shared keyPair = generateKeyPair()
    def publicKey = keyPair.publicKey()
    def privateKey = keyPair.privateKey()

    @Shared otherPublicKey = generateKeyPair().publicKey()

    abstract KeyPair generateKeyPair()
    abstract List<HashAlgorithm> supportedAlgorithms()

    @Unroll
    def 'can sign and verify using #algorithm'() {

        when:
            def signature = privateKey.sign(message, algorithm)

        then:
            publicKey.verify(signature, message)

        where:
            message = RandomStringUtils.random(60)
            algorithm << supportedAlgorithms()
    }

    def 'does not verify with different key'() {

        when:
            def signature = privateKey.sign(message)

        then:
            !otherPublicKey.verify(signature, message)

        where:
            message = RandomStringUtils.random(60)
    }

    def 'does not verify tampered data'() {

        when:
            def signature = privateKey.sign(message)

        then:
            !publicKey.verify(signature, tamperedMessage)

        where:
            message = RandomStringUtils.random(60)
            tamperedMessage = RandomStringUtils.random(60)
    }
}
