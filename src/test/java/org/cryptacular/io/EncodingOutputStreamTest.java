/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.io;

import java.io.ByteArrayOutputStream;
import java.io.File;
import org.bouncycastle.util.io.Streams;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link EncodingOutputStream} class.
 *
 * @author  Middleware Services
 */
public class EncodingOutputStreamTest
{
  @DataProvider(name = "plaintext-files")
  public Object[][] getPlaintextFiles()
  {
    return
      new Object[][] {
        new Object[] {"src/test/resources/plaintexts/lorem-1200.txt"},
        new Object[] {"src/test/resources/plaintexts/lorem-5000.txt"},
      };
  }

  @Test(dataProvider = "plaintext-files")
  public void testEncode(final String path)
    throws Exception
  {
    final File file = new File(path);
    String expectedPath = path + ".b64";
    if ("\r\n".equals(System.lineSeparator())) {
      expectedPath += ".crlf";
    }

    final String expected = new String(StreamUtil.readAll(expectedPath));
    final ByteArrayOutputStream bufOut = new ByteArrayOutputStream(
      (int) file.length() * 4 / 3);
    final EncodingOutputStream output = EncodingOutputStream.base64(bufOut, 64);
    try {
      Streams.pipeAll(StreamUtil.makeStream(file), output);
    } finally {
      StreamUtil.closeStream(output);
    }
    assertEquals(ByteUtil.toString(bufOut.toByteArray()), expected);
  }
}
