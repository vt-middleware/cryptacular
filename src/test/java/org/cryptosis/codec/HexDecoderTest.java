package org.cryptosis.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;

import org.cryptosis.ByteUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link HexDecoder} class.
 *
 * @author Marvin S. Addison
 */
public class HexDecoderTest
{
  @DataProvider(name = "hex-data")
  public Object[][] getHexData() {
    return new Object[][] {
      new Object[] {
        "41626c652077617320492065726520492073617720656c6261",
        "Able was I ere I saw elba"
      },
      new Object[] {
        "41626c652 077617320492065726520492073617720656c626\n1",
        "Able was I ere I saw elba"
      },
      new Object[] {
        "41626c652 077617320492065726520492073617720656c626\n",
        "Able was I ere I saw elb"
      }
    };
  }

  @Test(dataProvider = "hex-data")
  public void testDecode(final String encoded, final String expected) throws Exception
  {
    final HexDecoder decoder = new HexDecoder();
    final ByteBuffer output = ByteBuffer.allocate(decoder.outputSize(encoded.length()));
    decoder.decode(CharBuffer.wrap(encoded), output);
    decoder.finalize(output);
    output.flip();
    assertEquals(ByteUtil.toString(output), expected);
  }
}
