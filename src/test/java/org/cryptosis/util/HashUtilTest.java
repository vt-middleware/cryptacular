package org.cryptosis.util;

import java.io.File;
import java.io.InputStream;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link HashUtil}.
 *
 * @author Marvin S. Addison
 */
public class HashUtilTest
{
  private static final byte[] SALT = new byte[] {0, 1, 2, 3, 4, 5, 6, 7};

  @DataProvider(name = "salted-hash-iter")
  public Object[][] getSaltedHashData()
  {
    return new Object[][] {
      new Object[] {
        new SHA1Digest(),
        "deoxyribonucleic acid",
        null,
        1,
        "d1a0cce60feaa9f555ffc308aa44ca41a9255928",
      },
      new Object[] {
        new SHA1Digest(),
        "protoporphyrin-9",
        SALT,
        1,
        "e9269f1c8a13bac60de9d9cad69c71eee75a04b00001020304050607",
      },
      new Object[] {
        new SHA256Digest(),
        "N-arachidonoylethanolamine",
        SALT,
        5,
        "e9f2361c0ba0a4c4aec8d73316409e93f4cb8f3f1b30960d1be1d14a0aada9e50001020304050607",
      },
    };
  }


  @DataProvider(name = "file-hashes")
  public Object[][] getFileHashes()
  {
    return new Object[][] {
      new Object[] {
        "src/test/resources/plaintexts/lorem-1200.txt",
        "f0746e8978b3eccca05284dd12f098fdea32c8bc",
      },
      new Object[] {
        "src/test/resources/plaintexts/lorem-5000.txt",
        "1142d7a2661760624fa41b002be6c66c23b50602",
      },
    };
  }


  @Test(dataProvider = "salted-hash-iter")
  public void testSaltedHashIter(
    final Digest digest, final String data, final byte[] salt, final int iterations, final String expected)
    throws Exception
  {
    assertEquals(Hex.toHexString(HashUtil.hash(digest, data.getBytes("ASCII"), salt, iterations)), expected);
  }


  @Test(dataProvider = "file-hashes")
  public void testHashStream(final String path, final String expected) throws Exception
  {
    final InputStream in = StreamUtil.makeStream(new File(path));
    try {
      assertEquals(Hex.toHexString(HashUtil.sha1(in)), expected);
    } finally {
      in.close();
    }
  }
}
