package uk.org.lidalia.crypto.dsa

import uk.org.lidalia.hash.HashAlgorithm
import uk.org.lidalia.crypto.KeyPair
import uk.org.lidalia.crypto.SigningKeyTests

import static uk.org.lidalia.hash.HashAlgorithm.*
import static uk.org.lidalia.crypto.dsa.Dsa.DSA

class DsaKeyTests extends SigningKeyTests {

    @Override
    KeyPair generateKeyPair() {
        DSA.generateKeyPair(1024)
    }

    @Override
    List<HashAlgorithm> supportedAlgorithms() {
        [SHA1, SHA224, SHA256]
    }

    def 'create serialise and restore private key'() {

        given:
            def privateKeyEncoded = privateKey.bytes()

        expect:
            DsaPrivateKey.fromEncoded(privateKeyEncoded) == privateKey
    }

    def 'create serialise and restore public key'() {

        given:
            def publicKeyEncoded = publicKey.bytes()

        expect:
            DsaPublicKey.fromEncoded(publicKeyEncoded) == publicKey
    }
}
