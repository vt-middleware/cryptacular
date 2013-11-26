package org.cryptosis.codec;

import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.FileChannel;

import org.cryptosis.ByteUtil;
import org.cryptosis.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link Base64Encoder} class.
 *
 * @author Marvin S. Addison
 */
public class Base64EncoderTest
{
  @DataProvider(name = "text-data")
  public Object[][] getTextData() {
    return new Object[][] {
      new Object[] {
        "Able was I ere I saw elba",
        0,
        "QWJsZSB3YXMgSSBlcmUgSSBzYXcgZWxiYQ=="
      },
      new Object[] {
        "Able was I ere I saw elba.",
        0,
        "QWJsZSB3YXMgSSBlcmUgSSBzYXcgZWxiYS4="
      },
    };
  }


  @DataProvider(name = "plaintext-files")
  public Object[][] getPlaintextFiles()
  {
    return new Object[][] {
      new Object[] {"src/test/resources/plaintexts/lorem-1190.txt"},
      new Object[] {"src/test/resources/plaintexts/lorem-1200.txt"},
      new Object[] {"src/test/resources/plaintexts/lorem-5000.txt"},
    };
  }


  @Test(dataProvider = "text-data")
  public void testEncode(final String data, final int lineLength, final String expected) throws Exception
  {
    final ByteBuffer input = ByteUtil.toByteBuffer(data);
    final Base64Encoder encoder = new Base64Encoder(lineLength);
    final CharBuffer output = CharBuffer.allocate(encoder.outputSize(input.limit()));
    encoder.encode(input, output);
    encoder.finalize(output);
    assertEquals(output.flip().toString(), expected);
  }


  @Test(dataProvider = "plaintext-files")
  public void testEncodeFile(final String path) throws Exception
  {
    final File file = new File(path);
    final String expected = new String(StreamUtil.readAll(path + ".b64"));
    final StringBuilder actual = new StringBuilder(expected.length());
    final FileInputStream input = new FileInputStream(file);
    final Base64Encoder encoder = new Base64Encoder();
    try {
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
    } finally {
      input.close();
    }
    assertEquals(actual.toString(), expected);
  }
}
