package uk.org.lidalia.encoding.core;

import uk.org.lidalia.lang.Bytes;

/**
 * Type that allows encoding a value to some encoded form (e.g.
 * encoding some {@link Bytes} as {@link uk.org.lidalia.encoding.hex.Hex},
 * or constructing a validated encoded form from a raw encoded form
 * (e.g. a {@link uk.org.lidalia.encoding.hex.Hex} from a {@link String}).
 *
 * @param <Decoded> the type of the actual value that has been encoded
 *                 (in the case of a hex string, {@link Bytes})
 * @param <RawEncoded> the type of the encoding (in the case of a hex string,
 *                    a {@link String})
 * @param <E> the {@link Encoded} type
 */
public interface Encoder<Decoded, RawEncoded, E extends Encoded<Decoded, RawEncoded>> {

    /**
     * Validates a raw encoded value is a valid encoded form of the unencoded
     * type, and returns it wrapped in a type safe value that permits decoding
     *
     * @param encoded the raw encoded value (e.g. a hex string)
     * @return a validated and type safe wrapper around the encoded param
     * @throws InvalidEncoding if the encoded param is not a valid encoded form
     */
    E of(RawEncoded encoded) throws InvalidEncoding;

    /**
     * Encodes a value in some more general form
     *
     * @param decoded the original unencoded value
     * @return type safe encoded form of the value
     */
    E encode(Decoded decoded);

}
