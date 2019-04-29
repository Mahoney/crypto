package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.core.CachedEncodedBase;

public class SshPublicKeyString extends CachedEncodedBase<RsaPublicKey, String> {

    SshPublicKeyString(String raw, RsaPublicKey rsaPublicKey) {
        super(raw, rsaPublicKey);
    }

}
