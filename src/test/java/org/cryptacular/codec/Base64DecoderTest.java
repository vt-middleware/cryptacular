/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

import java.io.File;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;

import org.cryptacular.FailListener;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.CodecUtil;
import org.cryptacular.util.HashUtil;
import org.cryptacular.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link Base64Decoder} class.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class Base64DecoderTest
{

  @DataProvider(name = "encoded-data")
  public Object[][] getEncodedData()
  {
    return
      new Object[][] {
        new Object[] {
          new Base64Decoder(),
          "QWJsZSB3YXMgSSBlcmUgSSBzYXcgZWxiYQ==",
          ByteUtil.toBytes("Able was I ere I saw elba"),
        },
        new Object[] {
          new Base64Decoder(),
          "QWJsZSB3YXMgSSBlcmUgSSBzYXcgZWxiYS4=",
          ByteUtil.toBytes("Able was I ere I saw elba."),
        },
        new Object[] {
          new Base64Decoder(),
          "safx/LW8+SsSy/o3PmCNy4VEm5s=",
          HashUtil.sha1(ByteUtil.toBytes("t3stUs3r01")),
        },
        new Object[] {
          new Base64Decoder.Builder().setUrlSafe(true).build(),
          "safx_LW8-SsSy_o3PmCNy4VEm5s=",
          HashUtil.sha1(ByteUtil.toBytes("t3stUs3r01")),
        },
        new Object[] {
          new Base64Decoder.Builder().setUrlSafe(true).setPadding(false).build(),
          "FPu_A9l-",
          CodecUtil.hex("14FBBF03D97E"),
        },
        new Object[] {
          new Base64Decoder.Builder().setUrlSafe(true).setPadding(false).build(),
          "FPu_A9k",
          CodecUtil.hex("14FBBF03D9"),
        },
      };
  }


  @DataProvider(name = "plaintext-files")
  public Object[][] getPlaintextFiles()
  {
    return
      new Object[][] {
        new Object[] {"src/test/resources/plaintexts/lorem-1190.txt"},
        new Object[] {"src/test/resources/plaintexts/lorem-1200.txt"},
        new Object[] {"src/test/resources/plaintexts/lorem-5000.txt"},
      };
  }


  @Test(dataProvider = "encoded-data")
  public void testDecode(final Base64Decoder decoder, final String data, final byte[] expected)
    throws Exception
  {
    final CharBuffer input = CharBuffer.wrap(data);
    final ByteBuffer output = ByteBuffer.allocate(decoder.outputSize(input.length()));
    decoder.decode(input, output);
    decoder.finalize(output);
    output.flip();
    assertEquals(ByteUtil.toArray(output), expected);
  }


  @Test(dataProvider = "plaintext-files")
  public void testDecodeFile(final String path)
    throws Exception
  {
    final String expected = StreamUtil.readAll(StreamUtil.makeReader(new File(path)));
    final File file = new File(path + ".b64");
    final StringBuilder actual = new StringBuilder(expected.length());
    final Reader reader = StreamUtil.makeReader(file);
    final Base64Decoder decoder = new Base64Decoder();
    try {
      final CharBuffer bufIn = CharBuffer.allocate(1024);
      final ByteBuffer bufOut = ByteBuffer.allocate(decoder.outputSize(bufIn.capacity()));
      while (reader.read(bufIn) > 0) {
        bufIn.flip();
        decoder.decode(bufIn, bufOut);
        bufOut.flip();
        actual.append(ByteUtil.toCharBuffer(bufOut));
        bufOut.clear();
        bufIn.clear();
      }
      decoder.finalize(bufOut);
      bufOut.flip();
      actual.append(ByteUtil.toCharBuffer(bufOut));
    } finally {
      StreamUtil.closeReader(reader);
    }
    assertEquals(actual.toString(), expected);
  }
}
