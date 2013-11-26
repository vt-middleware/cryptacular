package org.cryptosis.io;

import org.bouncycastle.util.io.Streams;
import org.cryptosis.ByteUtil;
import org.cryptosis.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link DecodingInputStream} class.
 *
 * @author Marvin S. Addison
 */
public class DecodingInputStreamTest
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
  public void testDecode(final String path) throws Exception
  {
    final String expected = StreamUtil.readAll(StreamUtil.makeReader(new File(path)));
    final File file = new File(path + ".b64");
    final DecodingInputStream input = DecodingInputStream.base64(StreamUtil.makeStream(file));
    final ByteArrayOutputStream output = new ByteArrayOutputStream(expected.length());
    try {
      Streams.pipeAll(input, output);
    } finally {
      StreamUtil.closeStream(input);
      StreamUtil.closeStream(output);
    }
    assertEquals(ByteUtil.toString(output.toByteArray()), expected);
  }
}
