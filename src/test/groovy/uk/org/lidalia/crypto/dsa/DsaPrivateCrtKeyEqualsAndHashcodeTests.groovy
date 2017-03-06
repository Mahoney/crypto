package uk.org.lidalia.crypto.dsa

import spock.lang.Shared
import uk.org.lidalia.EqualsAndHashcodeTests
import uk.org.lidalia.crypto.dsa.DsaKeyPair
import uk.org.lidalia.crypto.dsa.DsaPrivateKey

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec

import static uk.org.lidalia.crypto.dsa.Dsa.DSA

class DsaPrivateCrtKeyEqualsAndHashcodeTests extends EqualsAndHashcodeTests<PrivateKey> {

    @Shared DsaKeyPair keyPair1 = DSA.generateKeyPair()
    @Shared DsaKeyPair keyPair2 = DSA.generateKeyPair()

    DsaPrivateKey instance1A = keyPair1.privateKey()
    PrivateKey instance1B = javaPrivateKey(instance1A.bytes().array())
    DsaPrivateKey instance1C = DsaPrivateKey.fromEncoded(instance1A.bytes())

    DsaPrivateKey instance2A = keyPair2.privateKey()
    PrivateKey instance2B = javaPrivateKey(instance2A.bytes().array())
    DsaPrivateKey instance2C = DsaPrivateKey.fromEncoded(instance2A.bytes())

    private static PrivateKey javaPrivateKey(byte[] bytes) {
        KeyFactory.getInstance('DSA').generatePrivate(new PKCS8EncodedKeySpec(bytes))
    }
}
