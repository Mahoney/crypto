package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.Encoder;
import uk.org.lidalia.encoding.InvalidEncoding;

import java.io.IOException;
import java.math.BigInteger;
import java.security.spec.RSAPrivateCrtKeySpec;

public class Pkcs1Encoder implements Encoder<RsaPrivateKey, Bytes, Pkcs1> {

    public static final Pkcs1Encoder pkcs1 = new Pkcs1Encoder();

    private Pkcs1Encoder() {}

    @Override
    public Pkcs1 of(Bytes encodedKey) throws InvalidEncoding {
        return new Pkcs1(encodedKey, doDecode(encodedKey));
    }

    @Override
    public Pkcs1 encode(RsaPrivateKey decoded) {
        throw new UnsupportedOperationException("Not implemented");
    }

    /**
     * Convert PKCS#1 encoded private key into RSAPrivateCrtKeySpec.
     *
     * <p/>The ASN.1 syntax for the private key with CRT is
     *
     * <pre>
     * --
     * -- Representation of RSA private key with information for the CRT algorithm.
     * --
     * RSAPrivateKey ::= SEQUENCE {
     *   version           Version,
     *   modulus           INTEGER,  -- n
     *   publicExponent    INTEGER,  -- e
     *   privateExponent   INTEGER,  -- d
     *   prime1            INTEGER,  -- p
     *   prime2            INTEGER,  -- q
     *   exponent1         INTEGER,  -- d mod (p-1)
     *   exponent2         INTEGER,  -- d mod (q-1)
     *   coefficient       INTEGER,  -- (inverse of q) mod p
     *   otherPrimeInfos   OtherPrimeInfos OPTIONAL
     * }
     * </pre>
     *
     * @param keyBytes PKCS#1 encoded key
     * @return KeySpec
     * @throws IOException
     */
    private static RsaPrivateKey doDecode(Bytes keyBytes) throws InvalidEncoding {

        try {

            DerParser parser = new DerParser(keyBytes.array());

            Asn1Object sequence = parser.read();
            if (sequence.getType() != DerParser.SEQUENCE)
                throw new IOException("Invalid DER: not a sequence"); //$NON-NLS-1$

            // Parse inside the sequence
            parser = sequence.getParser();

            parser.read(); // Skip version
            BigInteger modulus = parser.read().getInteger();
            BigInteger publicExp = parser.read().getInteger();
            BigInteger privateExp = parser.read().getInteger();
            BigInteger prime1 = parser.read().getInteger();
            BigInteger prime2 = parser.read().getInteger();
            BigInteger exp1 = parser.read().getInteger();
            BigInteger exp2 = parser.read().getInteger();
            BigInteger crtCoef = parser.read().getInteger();

            return RsaPrivateKey.of(
                    new RSAPrivateCrtKeySpec(
                            modulus, publicExp, privateExp, prime1, prime2,
                            exp1, exp2, crtCoef
                    )
            );
        } catch (Exception e) {
            throw new InvalidEncoding(keyBytes, "Unknown key format", e){};
        }
    }
}
