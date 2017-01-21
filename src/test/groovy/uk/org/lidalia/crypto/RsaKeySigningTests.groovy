package uk.org.lidalia.crypto

import uk.org.lidalia.crypto.rsa.RsaPrivateCrtKey
import uk.org.lidalia.crypto.rsa.RsaPublicKey

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class RsaKeySigningTests extends SigningKeyTests {

    @Override
    KeyPair generateKeyPair() {
        RSA.generateKeyPair()
    }

    @Override
    List<HashAlgorithm> supportedAlgorithms() {
        HashAlgorithm.values().toList()
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
