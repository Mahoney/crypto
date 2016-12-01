package uk.org.lidalia.encoding;

import org.junit.Test;
import uk.org.lidalia.encoding.base64.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;
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
        assertThat(encoded.getDecoded(), is("Any old string".getBytes(UTF_8)));
        assertThat(encoded.toDecodedString(), is("Any old string"));
    }
}
