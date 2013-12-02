package org.cryptosis.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

import org.cryptosis.util.ByteUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link HexEncoder} class.
 *
 * @author Marvin S. Addison
 */
public class HexEncoderTest
{
  @DataProvider(name = "text-data")
  public Object[][] getTextData() {
    return new Object[][] {
      new Object[] {
        "Able was I ere I saw elba",
        "41626c652077617320492065726520492073617720656c6261"
      },
      new Object[] {
        "Able was I ere I saw elba\n",
        "41626c652077617320492065726520492073617720656c62610a"
      },
    };
  }

  @Test(dataProvider = "text-data")
  public void testEncode(final String data, final String expected) throws Exception
  {
    final ByteBuffer input = ByteUtil.toByteBuffer(data);
    final HexEncoder encoder = new HexEncoder();
    final CharBuffer output = CharBuffer.allocate(encoder.outputSize(input.limit()));
    encoder.encode(input, output);
    encoder.finalize(output);
    assertEquals(output.flip().toString(), expected);
  }
}
