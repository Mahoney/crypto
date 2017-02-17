package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.Encoded;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

import static uk.org.lidalia.crypto.rsa.Pkcs1Encoder.pkcs1;

/**
 * Class for reading RSA private key from PEM file. It uses
 * the JMeter FileServer to find the file. So the file should
 * be located in the same directory as the test plan if the
 * path is relative.
 *
 * <p/>There is a cache so each file is only read once. If file
 * is changed, it will not take effect until the program
 * restarts.
 *
 * <p/>It can read PEM files with PKCS#8 or PKCS#1 encodings.
 * It doesn't support encrypted PEM files.
 *
 */
class Pkcs1 extends CachedEncodedBase<RsaPrivateKey, Bytes, Pkcs1> implements Encoded<RsaPrivateKey, Bytes, Pkcs1> {

    Pkcs1(Bytes raw, RsaPrivateKey decoded) throws InvalidEncoding {
        super(raw, decoded);
    }

    @Override
    public Encoder<RsaPrivateKey, Bytes, Pkcs1> encoder() {
        return pkcs1;
    }
}
