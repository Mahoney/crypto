package uk.org.lidalia.crypto.rsa

import spock.lang.Shared
import uk.org.lidalia.EqualsAndHashcodeTests

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.spec.PKCS8EncodedKeySpec

import static Pkcs8StringEncoder.pkcs8String
import static uk.org.lidalia.crypto.rsa.Pkcs8Encoder.pkcs8
import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class RsaPrivateCrtKeyEqualsAndHashcodeTests extends EqualsAndHashcodeTests<PrivateKey> {

    @Shared RsaPrivateKey keyPair1 = RSA.generateKeyPair()
    @Shared RsaPrivateKey keyPair2 = RSA.generateKeyPair()

    RsaPrivateKey instance1A = keyPair1.privateKey()
    PrivateKey instance1B = javaPrivateKey(instance1A.encode(pkcs8).raw().array())
    RsaPrivateKey instance1C = instance1A.encode(pkcs8String).decode()

    RsaPrivateKey instance2A = keyPair2.privateKey()
    PrivateKey instance2B = javaPrivateKey(instance2A.encode(pkcs8).raw().array())
    RsaPrivateKey instance2C = instance2A.encode(pkcs8String).decode()

    private static PrivateKey javaPrivateKey(byte[] bytes) {
        KeyFactory.getInstance('RSA').generatePrivate(new PKCS8EncodedKeySpec(bytes))
    }
}
