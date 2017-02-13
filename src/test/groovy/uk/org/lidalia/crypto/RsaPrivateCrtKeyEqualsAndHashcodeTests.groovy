package uk.org.lidalia.crypto

import spock.lang.Shared
import uk.org.lidalia.crypto.rsa.RsaPrivateKey

import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class RsaPrivateCrtKeyEqualsAndHashcodeTests extends EqualsAndHashcodeTests<java.security.PrivateKey> {

    @Shared RsaPrivateKey keyPair1 = RSA.generateKeyPair()
    @Shared RsaPrivateKey keyPair2 = RSA.generateKeyPair()

    RsaPrivateKey instance1A = keyPair1.privateKey()
    java.security.PrivateKey instance1B = javaPrivateKey(instance1A.bytes().array())
    RsaPrivateKey instance1C = RsaPrivateKey.fromEncoded(instance1A.bytes())

    RsaPrivateKey instance2A = keyPair2.privateKey()
    java.security.PrivateKey instance2B = javaPrivateKey(instance2A.bytes().array())
    RsaPrivateKey instance2C = RsaPrivateKey.fromEncoded(instance2A.bytes())

    private static java.security.PrivateKey javaPrivateKey(byte[] bytes) {
        KeyFactory.getInstance('RSA').generatePrivate(new PKCS8EncodedKeySpec(bytes))
    }
}
