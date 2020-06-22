package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.core.CachedEncodedBase;
import uk.org.lidalia.lang.Bytes;

public class SshPublicKey extends CachedEncodedBase<RsaPublicKey, Bytes> {

    SshPublicKey(Bytes bytes, RsaPublicKey decoded) {
        super(bytes, decoded);
    }

}
