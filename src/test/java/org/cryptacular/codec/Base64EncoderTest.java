/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.codec;

import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.FileChannel;
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
 * Unit test for {@link Base64Encoder} class.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class Base64EncoderTest
{
  @DataProvider(name = "byte-data")
  public Object[][] getByteData()
  {
    return
      new Object[][] {
        new Object[] {
          new Base64Encoder(),
          ByteUtil.toBytes("Able was I ere I saw elba"),
          "QWJsZSB3YXMgSSBlcmUgSSBzYXcgZWxiYQ==",
        },
        new Object[] {
          new Base64Encoder.Builder().setPadding(false).build(),
          ByteUtil.toBytes("Able was I ere I saw elba"),
          "QWJsZSB3YXMgSSBlcmUgSSBzYXcgZWxiYQ",
        },
        new Object[] {
          new Base64Encoder(),
          ByteUtil.toBytes("Able was I ere I saw elba."),
          "QWJsZSB3YXMgSSBlcmUgSSBzYXcgZWxiYS4=",
        },
        new Object[] {
          new Base64Encoder(),
          HashUtil.sha1(ByteUtil.toBytes("t3stUs3r01")),
          "safx/LW8+SsSy/o3PmCNy4VEm5s=",
        },
        new Object[] {
          new Base64Encoder(true),
          HashUtil.sha1(ByteUtil.toBytes("t3stUs3r01")),
          "safx_LW8-SsSy_o3PmCNy4VEm5s=",
        },
        new Object[] {
          new Base64Encoder(),
          CodecUtil.hex("3f1c435a244f7a8be1572a1bf2a196f4958cc00c17b96e"),
          "PxxDWiRPeovhVyob8qGW9JWMwAwXuW4=",
        },
        new Object[] {
          new Base64Encoder.Builder().setUrlSafe(true).setPadding(false).build(),
          CodecUtil.hex("14FBBF03D97E"),
          "FPu_A9l-",
        },
        new Object[] {
          new Base64Encoder.Builder().setUrlSafe(true).setPadding(false).build(),
          CodecUtil.hex("14FBBF03D9"),
          "FPu_A9k",
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


  @Test(dataProvider = "byte-data")
  public void testEncode(final Base64Encoder encoder, final byte[] inBytes, final String expected)
    throws Exception
  {
    final ByteBuffer input = ByteBuffer.wrap(inBytes);
    final CharBuffer output = CharBuffer.allocate(encoder.outputSize(input.limit()));
    encoder.encode(input, output);
    encoder.finalize(output);
    assertEquals(output.flip().toString(), expected);
  }


  @Test(dataProvider = "plaintext-files")
  public void testEncodeFile(final String path)
    throws Exception
  {
    final File file = new File(path);
    String expectedPath = path + ".b64";
    if ("\r\n".equals(System.lineSeparator())) {
      expectedPath += ".crlf";
    }

    final String expected = new String(StreamUtil.readAll(expectedPath));
    final StringBuilder actual = new StringBuilder(expected.length());
    final Base64Encoder encoder = new Base64Encoder(64);
    try (FileInputStream input = new FileInputStream(file)) {
      final ByteBuffer bufIn = ByteBuffer.allocate(512);
      final CharBuffer bufOut = CharBuffer.allocate(encoder.outputSize(512));
      final FileChannel chIn = input.getChannel();
      while (chIn.read(bufIn) > 0) {
        bufIn.flip();
        encoder.encode(bufIn, bufOut);
        bufOut.flip();
        actual.append(bufOut);
        bufOut.clear();
        bufIn.clear();
      }
      encoder.finalize(bufOut);
      bufOut.flip();
      actual.append(bufOut);
    }
    assertEquals(actual.toString(), expected);
  }
}
