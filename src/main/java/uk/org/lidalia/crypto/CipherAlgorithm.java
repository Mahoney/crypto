package uk.org.lidalia.crypto;

public class CipherAlgorithm {

    public static final CipherAlgorithm EcbPkcs1 = new CipherAlgorithm("ECB/PKCS1Padding");
    public static final CipherAlgorithm EcbOaepWithSha1AndMgf1 = new CipherAlgorithm("ECB/OAEPWithSHA-1AndMGF1Padding");

    private final String cipherPaddingName;

    public CipherAlgorithm(String cipherPaddingName) {

        this.cipherPaddingName = cipherPaddingName;
    }

    @Override
    public String toString() {
        return cipherPaddingName;
    }
}
