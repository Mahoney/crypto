package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class SshPublicKeyEncoderTests extends EncoderTests<RsaPublicKey, String, SshPublicKeyString> {

    SshPublicKeyEncoder encoder = SshPublicKeyEncoder.sshPublicKey

    private static final RsaPrivateKey cached1 = RSA.generateKeyPair(1024)
    RsaPublicKey instance1 = cached1.publicKey()

    private static final RsaPrivateKey cached2 = RSA.generateKeyPair(1024)
    RsaPublicKey instance2 = cached2.publicKey()
}
