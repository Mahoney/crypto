package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Shared
import spock.lang.Specification
import spock.lang.Unroll
import uk.org.lidalia.crypto.rsa.Rsa

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class RsaKeyTest extends Specification {

    static keyPair = RSA.generateKeyPair()
    def publicKey = keyPair.publicKey()
    def privateKey = keyPair.privateKey()

    @Unroll
    def 'can encrypt and decrypt using algorithm #algorithm'() {

        when:
            def encrypted = publicKey.encrypt(decrypted, algorithm)

        then:
            privateKey.decrypt(encrypted, algorithm).string() == decrypted

        where:
            decrypted = RandomStringUtils.random(60)
            algorithm << [
                    Rsa.RsaEcbOaepWithSha1AndMgf1Padding,
                    Rsa.RsaEcbOaepWithSha256AndMgf1Padding,
                    Rsa.RsaEcbPkcs1Padding,
            ]
    }

    @Unroll
    def 'can sign and verify using #algorithm'() {

        when:
            def signature = privateKey.sign(message, algorithm)

        then:
            publicKey.verify(signature, message)

        where:
            message = RandomStringUtils.random(60)
            algorithm << HashAlgorithm.values().toList()
    }
}
