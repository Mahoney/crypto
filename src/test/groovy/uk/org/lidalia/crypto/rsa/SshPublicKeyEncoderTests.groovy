package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

class SshPublicKeyEncoderTests extends EncoderTests<RsaPublicKey, String, SshPublicKeyString> {

    SshPublicKeyEncoder encoder = SshPublicKeyEncoder.sshPublicKey

    private static final RsaPrivateKey cached1 = RsaPrivateKey.generate()
    RsaPublicKey instance1 = cached1.publicKey()

    private static final RsaPrivateKey cached2 = RsaPrivateKey.generate()
    RsaPublicKey instance2 = cached2.publicKey()
}
