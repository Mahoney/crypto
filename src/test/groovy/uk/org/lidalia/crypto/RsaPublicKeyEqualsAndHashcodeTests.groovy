package uk.org.lidalia.crypto

import spock.lang.Shared
import uk.org.lidalia.crypto.rsa.RsaPrivateCrtKey
import uk.org.lidalia.crypto.rsa.RsaPublicKey

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class RsaPublicKeyEqualsAndHashcodeTests extends EqualsAndHashcodeTests<RsaPublicKey> {

    @Shared RsaPrivateCrtKey keyPair1 = RSA.generateKeyPair()
    @Shared RsaPrivateCrtKey keyPair2 = RSA.generateKeyPair()

    RsaPublicKey instance1 = keyPair1.publicKey()
    RsaPublicKey equalToInstance1 = RsaPublicKey.fromEncoded(instance1.bytes())

    RsaPublicKey instance2 = keyPair2.publicKey()
    RsaPublicKey equalToInstance2 = RsaPublicKey.fromEncoded(instance2.bytes())

}
