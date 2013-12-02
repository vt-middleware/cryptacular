package org.cryptosis.io;

import java.io.ByteArrayOutputStream;
import java.io.File;

import org.bouncycastle.util.io.Streams;
import org.cryptosis.util.ByteUtil;
import org.cryptosis.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link EncodingOutputStream} class.
 *
 * @author Marvin S. Addison
 */
public class EncodingOutputStreamTest
{
  @DataProvider(name = "plaintext-files")
  public Object[][] getPlaintextFiles()
  {
    return new Object[][] {
      new Object[] {"src/test/resources/plaintexts/lorem-1200.txt"},
      new Object[] {"src/test/resources/plaintexts/lorem-5000.txt"},
    };
  }

  @Test(dataProvider = "plaintext-files")
  public void testEncode(final String path) throws Exception
  {
    final File file = new File(path);
    final String expected = new String(StreamUtil.readAll(path + ".b64"));
    final ByteArrayOutputStream bufOut = new ByteArrayOutputStream((int) file.length() * 4 / 3);
    final EncodingOutputStream output = EncodingOutputStream.base64(bufOut);
    try {
      Streams.pipeAll(StreamUtil.makeStream(file), output);
    } finally {
      StreamUtil.closeStream(output);
    }
    assertEquals(ByteUtil.toString(bufOut.toByteArray()), expected);
  }
}
