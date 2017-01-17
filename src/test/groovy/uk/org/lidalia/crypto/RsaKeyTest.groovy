package uk.org.lidalia.crypto

import org.apache.commons.lang3.RandomStringUtils
import spock.lang.Unroll
import uk.org.lidalia.crypto.rsa.Rsa
import uk.org.lidalia.crypto.rsa.RsaPrivateCrtKey
import uk.org.lidalia.crypto.rsa.RsaPublicKey
import uk.org.lidalia.encoding.Bytes

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class RsaKeyTest extends AsymmetricKeyTests {

    @Override
    KeyPair generateKeyPair() {
        RSA.generateKeyPair()
    }

    @Override
    List<HashAlgorithm> supportedAlgorithms() {
        HashAlgorithm.values().toList()
    }

    @Unroll
    def 'can encrypt and decrypt using algorithm #algorithm'() {

        when:
            def encrypted = publicKey.encrypt(decrypted, algorithm)

        then:
            encrypted != decrypted
            privateKey.decrypt(encrypted, algorithm) == decrypted

        where:
            decrypted = Bytes.of(RandomStringUtils.random(60))
            algorithm << [
                    Rsa.RsaEcbOaepWithSha1AndMgf1Padding,
                    Rsa.RsaEcbOaepWithSha256AndMgf1Padding,
                    Rsa.RsaEcbPkcs1Padding,
            ]
    }

    def 'create serialise and restore private key'() {

        given:
            def privateKeyEncoded = privateKey.bytes()

        expect:
            RsaPrivateCrtKey.fromEncoded(privateKeyEncoded) == privateKey
    }

    def 'create serialise and restore public key'() {

        given:
            def publicKeyEncoded = publicKey.bytes()

        expect:
            RsaPublicKey.fromEncoded(publicKeyEncoded) == publicKey
    }
}
