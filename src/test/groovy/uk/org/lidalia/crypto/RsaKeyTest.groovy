package uk.org.lidalia.crypto

import spock.lang.Specification
import spock.lang.Unroll
import uk.org.lidalia.crypto.rsa.Rsa

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class RsaKeyTest extends Specification {

    @Unroll
    def 'can encrypt and decrypt for algorithm #algorithm'() {

        given:
            def keyPair = RSA.generateKeyPair()
            def publicKey = keyPair.publicKey()
            def privateKey = keyPair.privateKey()

        when:
            def encrypted = publicKey.encrypt(decrypted, algorithm)

        then:
            privateKey.decrypt(encrypted, algorithm).string() == decrypted

        where:
            decrypted = "Some text"
            algorithm << [
                    Rsa.RsaEcbOaepWithSha1AndMgf1Padding,
                    Rsa.RsaEcbOaepWithSha256AndMgf1Padding,
                    Rsa.RsaEcbPkcs1Padding,
            ]
    }
}
