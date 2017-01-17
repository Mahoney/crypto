package uk.org.lidalia.crypto

import spock.lang.Shared
import uk.org.lidalia.crypto.rsa.RsaPrivateCrtKey

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class RsaPrivateCrtKeyEqualsAndHashcodeTests extends EqualsAndHashcodeTests<RsaPrivateCrtKey> {

    @Shared RsaPrivateCrtKey keyPair1 = RSA.generateKeyPair()
    @Shared RsaPrivateCrtKey keyPair2 = RSA.generateKeyPair()

    RsaPrivateCrtKey instance1 = keyPair1.privateKey()
    RsaPrivateCrtKey equalToInstance1 = RsaPrivateCrtKey.fromEncoded(instance1.bytes())
    RsaPrivateCrtKey instance2 = keyPair2.privateKey()
    RsaPrivateCrtKey equalToInstance2 = RsaPrivateCrtKey.fromEncoded(instance2.bytes())

}
