package uk.org.lidalia.crypto;

public enum CipherPadding {

    EcbPkcs1("/ECB/PKCS1Padding");

    private final String cipherPaddingName;

    CipherPadding(String cipherPaddingName) {

        this.cipherPaddingName = cipherPaddingName;
    }

    @Override
    public String toString() {
        return cipherPaddingName;
    }
}
