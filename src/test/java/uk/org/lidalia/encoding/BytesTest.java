package uk.org.lidalia.encoding;

import org.junit.Test;
import uk.org.lidalia.lang.Bytes;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

public class BytesTest {

    @Test
    public void toStringFormat() {
        assertThat(Bytes.of("Hello World").toString(), is("[72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100]"));
    }

}
