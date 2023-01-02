package uk.org.lidalia.crypto

import uk.org.lidalia.EqualsAndHashcodeTests
import uk.org.lidalia.crypto.dsa.Dsa
import uk.org.lidalia.crypto.rsa.Rsa

import static uk.org.lidalia.crypto.dsa.Dsa.DSA
import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class AsymmetricCryptoAlgorithmEqualsAndHashcodeTests extends EqualsAndHashcodeTests<AsymmetricCryptoAlgorithm> {

    Rsa instance1A = RSA
    Rsa instance1B = RSA
    Rsa instance1C = RSA

    Dsa instance2A = DSA
    Dsa instance2B = DSA
    Dsa instance2C = DSA
}
