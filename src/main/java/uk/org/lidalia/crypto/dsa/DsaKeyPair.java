package uk.org.lidalia.crypto.dsa;

import uk.org.lidalia.crypto.KeyPair;

import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;

public class DsaKeyPair implements KeyPair<Dsa> {

    public static DsaKeyPair from(java.security.KeyPair keyPair) {
        return new DsaKeyPair(keyPair);
    }

    private final DsaPublicKey publicKey;
    private final DsaPrivateKey privateKey;
    private final java.security.KeyPair keyPair;

    private DsaKeyPair(java.security.KeyPair keyPair) {
        this.keyPair = keyPair;
        this.publicKey = DsaPublicKey.from((DSAPublicKey) keyPair.getPublic());
        this.privateKey = DsaPrivateKey.from((DSAPrivateKey) keyPair.getPrivate());
    }

    @Override
    public DsaPublicKey publicKey() {
        return publicKey;
    }

    @Override
    public DsaPrivateKey privateKey() {
        return privateKey;
    }

    @Override
    public Dsa algorithm() {
        return Dsa.DSA;
    }

    @Override
    public java.security.KeyPair toJavaKeyPair() {
        return keyPair;
    }
}
