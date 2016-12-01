package uk.org.lidalia.encoding;

import org.junit.Test;
import uk.org.lidalia.encoding.base64.Base64;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;
import static uk.org.lidalia.encoding.base64.Base64Encoder.base64;

public class Base64Tests {

    @Test
    public void encodesAsBase64() {

        // given:
        Base64 encoded = base64.encode("Any old string");

        // expect:
        assertThat(encoded.toString(), is("QW55IG9sZCBzdHJpbmc="));
        assertThat(encoded.getDecoded(), is(Bytes.of("Any old string")));
        assertThat(encoded.getDecoded().asString(), is("Any old string"));
    }
}
