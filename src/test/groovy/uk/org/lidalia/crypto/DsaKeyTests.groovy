package uk.org.lidalia.crypto

import uk.org.lidalia.crypto.dsa.DsaPrivateKey
import uk.org.lidalia.crypto.dsa.DsaPublicKey

import static uk.org.lidalia.crypto.HashAlgorithm.SHA1
import static uk.org.lidalia.crypto.HashAlgorithm.SHA224
import static uk.org.lidalia.crypto.HashAlgorithm.SHA256
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
