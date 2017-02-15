package uk.org.lidalia.crypto.rsa

import uk.org.lidalia.crypto.CipherAlgorithm
import uk.org.lidalia.crypto.CryptoKeyTests
import uk.org.lidalia.crypto.DecryptKey
import uk.org.lidalia.crypto.EncryptKey
import uk.org.lidalia.crypto.rsa.Rsa

import static uk.org.lidalia.crypto.rsa.Rsa.RSA

class RsaKeyCryptoTests extends CryptoKeyTests {

    @Override
    Tuple2<EncryptKey, DecryptKey> generateKeyPair() {
        def pair = RSA.generateKeyPair()
        new Tuple2<>(pair.publicKey(), pair.privateKey())
    }

    @Override
    List<CipherAlgorithm> supportedAlgorithms() {
        [Rsa.RsaEcbPkcs1Padding, Rsa.RsaEcbOaepWithSha1AndMgf1Padding, Rsa.RsaEcbOaepWithSha256AndMgf1Padding]
    }

    @Override
    CipherAlgorithm defaultAlgorithm() {
        Rsa.RsaEcbPkcs1Padding
    }
}
