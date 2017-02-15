package uk.org.lidalia.crypto.rsa;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.lang.Pair;

import java.io.*;
import java.math.BigInteger;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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
class PrivateKeyReader {

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
    static RSAPrivateCrtKeySpec getRsaPrivateKeySpec(byte[] keyBytes) throws IOException  {

        DerParser parser = new DerParser(keyBytes);

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

        return new RSAPrivateCrtKeySpec(
                modulus, publicExp, privateExp, prime1, prime2,
                exp1, exp2, crtCoef);
    }
}
