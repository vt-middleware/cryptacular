/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import org.cryptacular.FailListener;
import org.cryptacular.util.ByteUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link HexDecoder} class.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class HexDecoderTest
{
  @DataProvider(name = "hex-data")
  public Object[][] getHexData()
  {
    return
      new Object[][] {
        new Object[] {
          "41626c652077617320492065726520492073617720656c6261",
          "Able was I ere I saw elba",
        },
        new Object[] {
          "41626c652 077617320492065726520492073617720656c626\n1",
          "Able was I ere I saw elba",
        },
        new Object[] {
          "41626c652 077617320492065726520492073617720656c626\n",
          "Able was I ere I saw elb",
        },
        new Object[] {
          "41:62:6c:65:20:77:61:73:20:49:20:65:72:65:20:49:20:73:61:77:20:65:6c:62:61",
          "Able was I ere I saw elba",
        },
        new Object[] {
          "9c63b0547798b60d5e04",
          ByteUtil.toString(
            new byte[] {
              (byte) -100,
              (byte) 99,
              (byte) -80,
              (byte) 84,
              (byte) 119,
              (byte) -104,
              (byte) -74,
              (byte) 13,
              (byte) 94,
              (byte) 4,
            }),
        },
      };
  }

  @Test(dataProvider = "hex-data")
  public void testDecode(final String encoded, final String expected)
    throws Exception
  {
    final HexDecoder decoder = new HexDecoder();
    final ByteBuffer output = ByteBuffer.allocate(decoder.outputSize(encoded.length()));
    decoder.decode(CharBuffer.wrap(encoded), output);
    decoder.finalize(output);
    output.flip();
    assertEquals(ByteUtil.toString(output), expected);
  }
}
