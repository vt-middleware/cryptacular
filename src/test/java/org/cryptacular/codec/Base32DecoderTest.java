/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.CodecUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link Base64Decoder}.
 *
 * @author  Middleware Services
 */
public class Base32DecoderTest
{
  @DataProvider(name = "encoded-data")
  public Object[][] getEncodedData()
  {
    return
      new Object[][] {
        // Multiple of 40 bits
        new Object[] {
          new Base32Decoder(),
          "TQSN7XJ4",
          CodecUtil.hex("9c24dfdd3c"),
        },
        // Final quantum of encoding input is exactly 8 bits
        new Object[] {
          new Base32Decoder(),
          "43H7CNN2EI======",
          CodecUtil.hex("e6cff135ba22"),
        },
        // Final quantum of encoding input is exactly 16 bits
        new Object[] {
          new Base32Decoder(),
          "2NEK2FDJHXDQ====",
          CodecUtil.hex("d348ad14693dc7"),
        },
        // Final quantum of encoding input is exactly 24 bits
        new Object[] {
          new Base32Decoder(),
          "LVVECZIT6F3MU===",
          CodecUtil.hex("5d6a416513f176ca"),
        },
        // Final quantum of encoding input is exactly 32 bits
        new Object[] {
          new Base32Decoder(),
          "QN5Z7HN4PBY4G5Q=",
          CodecUtil.hex("837b9f9dbc7871c376"),
        },
      };
  }


  @Test(dataProvider = "encoded-data")
  public void testDecode(final Base32Decoder decoder, final String data, final byte[] expected)
    throws Exception
  {
    final CharBuffer input = CharBuffer.wrap(data);
    final ByteBuffer output = ByteBuffer.allocate(decoder.outputSize(input.length()));
    decoder.decode(input, output);
    decoder.finalize(output);
    output.flip();
    assertEquals(ByteUtil.toArray(output), expected);
  }
}
