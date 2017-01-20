package uk.org.lidalia.crypto

import spock.lang.Shared
import uk.org.lidalia.crypto.dsa.DsaKeyPair
import uk.org.lidalia.crypto.dsa.DsaPublicKey

import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec

import static uk.org.lidalia.crypto.dsa.Dsa.DSA

class DsaPublicKeyEqualsAndHashcodeTests extends EqualsAndHashcodeTests<java.security.PublicKey> {

    @Shared DsaKeyPair keyPair1 = DSA.generateKeyPair()
    @Shared DsaKeyPair keyPair2 = DSA.generateKeyPair()

    DsaPublicKey instance1A = keyPair1.publicKey()
    java.security.PublicKey instance1B = javaPublicKey(instance1A.bytes().array())
    DsaPublicKey instance1C = DsaPublicKey.fromEncoded(instance1A.bytes())

    DsaPublicKey instance2A = keyPair2.publicKey()
    java.security.PublicKey instance2B = javaPublicKey(instance2A.bytes().array())
    DsaPublicKey instance2C = DsaPublicKey.fromEncoded(instance2A.bytes())

    private static java.security.PublicKey javaPublicKey(byte[] bytes) {
        KeyFactory.getInstance('DSA').generatePublic(new X509EncodedKeySpec(bytes))
    }
}
