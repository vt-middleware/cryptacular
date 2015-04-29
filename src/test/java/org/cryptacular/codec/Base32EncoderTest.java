/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

import org.cryptacular.FailListener;
import org.cryptacular.util.CodecUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link Base64Encoder}.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class Base32EncoderTest
{
  @DataProvider(name = "byte-data")
  public Object[][] getByteData()
  {
    return
      new Object[][] {
        // Multiple of 40 bits
        new Object[] {
          new Base32Encoder(),
          CodecUtil.hex("9c24dfdd3c"),
          "TQSN7XJ4",
        },
        // Final quantum of encoding input is exactly 8 bits
        new Object[] {
          new Base32Encoder(),
          CodecUtil.hex("e6cff135ba22"),
          "43H7CNN2EI======",
        },
        // Final quantum of encoding input is exactly 16 bits
        new Object[] {
          new Base32Encoder(),
          CodecUtil.hex("d348ad14693dc7"),
          "2NEK2FDJHXDQ====",
        },
        // Final quantum of encoding input is exactly 24 bits
        new Object[] {
          new Base32Encoder(),
          CodecUtil.hex("5d6a416513f176ca"),
          "LVVECZIT6F3MU===",
        },
        // Final quantum of encoding input is exactly 32 bits
        new Object[] {
          new Base32Encoder(),
          CodecUtil.hex("837b9f9dbc7871c376"),
          "QN5Z7HN4PBY4G5Q=",
        },
      };
  }

  @Test(dataProvider = "byte-data")
  public void testEncode(final Base32Encoder encoder, final byte[] inBytes, final String expected)
    throws Exception
  {
    final ByteBuffer input = ByteBuffer.wrap(inBytes);
    final CharBuffer output = CharBuffer.allocate(encoder.outputSize(input.limit()));
    encoder.encode(input, output);
    encoder.finalize(output);
    assertEquals(output.flip().toString(), expected);
  }

}
