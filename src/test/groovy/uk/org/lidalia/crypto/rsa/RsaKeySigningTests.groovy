package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.crypto.HashAlgorithm
import uk.org.lidalia.crypto.KeyPair
import uk.org.lidalia.crypto.SigningKeyTests
import uk.org.lidalia.crypto.rsa.RsaPrivateKey
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
            RsaPrivateKey.fromEncoded(privateKeyEncoded) == privateKey
    }

    def 'create serialise and restore public key'() {

        given:
            def publicKeyEncoded = publicKey.bytes()

        expect:
            RsaPublicKey.fromEncoded(publicKeyEncoded) == publicKey
    }
}
