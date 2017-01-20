package uk.org.lidalia.crypto

import spock.lang.Shared
import uk.org.lidalia.crypto.rsa.RsaPrivateCrtKey

import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class RsaPrivateCrtKeyEqualsAndHashcodeTests extends EqualsAndHashcodeTests<java.security.PrivateKey> {

    @Shared RsaPrivateCrtKey keyPair1 = RSA.generateKeyPair()
    @Shared RsaPrivateCrtKey keyPair2 = RSA.generateKeyPair()

    RsaPrivateCrtKey instance1A = keyPair1.privateKey()
    java.security.PrivateKey instance1B = javaPrivateKey(instance1A.bytes().array())
    RsaPrivateCrtKey instance1C = RsaPrivateCrtKey.fromEncoded(instance1A.bytes())

    RsaPrivateCrtKey instance2A = keyPair2.privateKey()
    java.security.PrivateKey instance2B = javaPrivateKey(instance2A.bytes().array())
    RsaPrivateCrtKey instance2C = RsaPrivateCrtKey.fromEncoded(instance2A.bytes())

    private static java.security.PrivateKey javaPrivateKey(byte[] bytes) {
        KeyFactory.getInstance('RSA').generatePrivate(new PKCS8EncodedKeySpec(bytes))
    }
}
