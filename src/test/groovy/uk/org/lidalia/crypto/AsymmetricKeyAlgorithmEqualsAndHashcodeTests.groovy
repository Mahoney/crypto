package uk.org.lidalia.crypto

import uk.org.lidalia.crypto.dsa.Dsa
import uk.org.lidalia.crypto.rsa.Rsa

import static uk.org.lidalia.crypto.rsa.Rsa.RSA
import static uk.org.lidalia.crypto.dsa.Dsa.DSA

class AsymmetricKeyAlgorithmEqualsAndHashcodeTests extends EqualsAndHashcodeTests<AsymmetricKeyAlgorithm> {

    Rsa instance1A = RSA
    Rsa instance1B = RSA
    Rsa instance1C = RSA

    Dsa instance2A = DSA
    Dsa instance2B = DSA
    Dsa instance2C = DSA
}
