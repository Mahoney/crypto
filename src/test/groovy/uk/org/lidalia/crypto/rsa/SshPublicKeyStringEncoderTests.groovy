package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.encoding.EncoderTests

class SshPublicKeyStringEncoderTests extends EncoderTests<RsaPublicKey, String, SshPublicKeyString> {

    SshPublicKeyStringEncoder encoder = SshPublicKeyStringEncoder.sshPublicKeyString

    private static final RsaPrivateKey cached1 = RsaPrivateKey.generate()
    RsaPublicKey instance1 = cached1.publicKey()

    private static final RsaPrivateKey cached2 = RsaPrivateKey.generate()
    RsaPublicKey instance2 = cached2.publicKey()

    def 'round trip example'() {

        when:
            def encoded = encoder.encode(instance1)

        then:
            encoded.raw() ==~ $/ssh-rsa [A-Za-z0-9+/]*=*/$

        when:
            def fromRaw = encoder.of(encoded.raw())

        then:
            fromRaw == encoded
            encoded.decode() == instance1
            fromRaw.decode() == instance1
    }
}
