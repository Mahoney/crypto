package uk.org.lidalia.crypto.rsa

import spock.lang.Shared
import uk.org.lidalia.EqualsAndHashcodeTests

import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class RsaPublicKeyEqualsAndHashcodeTests extends EqualsAndHashcodeTests<java.security.PublicKey> {

    @Shared RsaPrivateKey keyPair1 = RSA.generateKeyPair()
    @Shared RsaPrivateKey keyPair2 = RSA.generateKeyPair()

    RsaPublicKey instance1A = keyPair1.publicKey()
    java.security.PublicKey instance1B = javaPublicKey(instance1A.bytes().array())
    RsaPublicKey instance1C = RsaPublicKey.of(instance1A.bytes())

    RsaPublicKey instance2A = keyPair2.publicKey()
    java.security.PublicKey instance2B = javaPublicKey(instance2A.bytes().array())
    RsaPublicKey instance2C = RsaPublicKey.of(instance2A.bytes())

    private static java.security.PublicKey javaPublicKey(byte[] bytes) {
        KeyFactory.getInstance('RSA').generatePublic(new X509EncodedKeySpec(bytes))
    }
}
