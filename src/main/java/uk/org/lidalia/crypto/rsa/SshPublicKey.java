package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.lang.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;

public class SshPublicKey extends CachedEncodedBase<RsaPublicKey, Bytes> {

    SshPublicKey(Bytes bytes, RsaPublicKey decoded) {
        super(bytes, decoded);
    }

}
