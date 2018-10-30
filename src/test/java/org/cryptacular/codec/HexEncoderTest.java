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
 * Unit test for {@link HexEncoder} class.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class HexEncoderTest
{
  @DataProvider(name = "text-data")
  public Object[][] getTextData()
  {
    return
      new Object[][] {
        new Object[] {
          new HexEncoder(false),
          ByteUtil.toBytes("Able was I ere I saw elba"),
          "41626c652077617320492065726520492073617720656c6261",
        },
        new Object[] {
          new HexEncoder(false, true),
          ByteUtil.toBytes("Able was I ere I saw elba\n"),
          "41626C652077617320492065726520492073617720656C62610A",
        },
        new Object[] {
          new HexEncoder(true),
          ByteUtil.toBytes("Able was I ere I saw elba"),
          "41:62:6c:65:20:77:61:73:20:49:20:65:72:65:20:49:20:73:61:77:20:65:6c:62:61",
        },
        new Object[] {
          new HexEncoder(),
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
          },
          "9c63b0547798b60d5e04",
        },
      };
  }

  @Test(dataProvider = "text-data")
  public void testEncode(final HexEncoder encoder, final byte[] data, final String expected)
    throws Exception
  {
    final CharBuffer output = CharBuffer.allocate(encoder.outputSize(data.length));
    encoder.encode(ByteBuffer.wrap(data), output);
    encoder.finalize(output);
    assertEquals(output.flip().toString(), expected);
  }
}
