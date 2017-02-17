package uk.org.lidalia.encoding.hex;

import uk.org.lidalia.encoding.Bytes;
import uk.org.lidalia.encoding.CachedEncodedBase;
import uk.org.lidalia.encoding.EncodedBytes;

import static uk.org.lidalia.encoding.hex.HexEncoder.hex;

public class Hex extends CachedEncodedBase<Bytes, String, Hex> implements EncodedBytes<Hex> {

    Hex(String encoded, Bytes decoded) {
        super(encoded, decoded);
    }

    public HexEncoder encoder() {
        return hex;
    }
}
