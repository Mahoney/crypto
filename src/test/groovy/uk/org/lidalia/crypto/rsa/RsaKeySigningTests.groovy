package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.hash.HashAlgorithm
import uk.org.lidalia.crypto.KeyPair
import uk.org.lidalia.crypto.SigningKeyTests

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class RsaKeySigningTests extends SigningKeyTests {

    @Override
    KeyPair generateKeyPair() {
        RSA.generateKeyPair(1024)
    }

    @Override
    List<HashAlgorithm> supportedAlgorithms() {
        HashAlgorithm.values().toList()
    }
}
