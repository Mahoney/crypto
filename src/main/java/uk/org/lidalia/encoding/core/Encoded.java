package uk.org.lidalia.encoding.core;

import uk.org.lidalia.lang.Bytes;

/**
 * Represents an encoded form of some value - for instance, a byte[] encoded as a hex string.
 * Should be validated as part of construction - that is, calling either method on this interface
 * should never result in an Exception.
 *
 * @param <Decoded> the type of the actual value that has been encoded (in the case of a hex string, {@link Bytes})
 * @param <Raw> the type of the encoding (in the case of a hex string, a {@link String})
 */
public interface Encoded<Decoded, Raw> {

    /**
     * @return the original unencoded value
     */
    Decoded decode();

    /**
     * @return the raw encoded form
     */
    Raw raw();

}
