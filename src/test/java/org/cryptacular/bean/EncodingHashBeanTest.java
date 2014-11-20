/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import org.cryptacular.spec.CodecSpec;
import org.cryptacular.spec.DigestSpec;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.CodecUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Unit test for {@link EncodingHashBean}.
 *
 * @author  Middleware Services
 */
public class EncodingHashBeanTest
{
  @DataProvider(name = "hash-data")
  public Object[][] getHashData()
  {
    return
      new Object[][] {
        {
          new DigestSpec("SHA1"),
          CodecSpec.BASE64,
          new Object[] {
            CodecUtil.b64("7FHsteHnm6XQsJT1TTKbxw=="),
            CodecUtil.b64("ehp6PCnojSegFpRvStqQ9A=="),
          },
          1,
          "Oadnuuj7QsRPUuMBiu+dmlT6qzU=",
        },
        {
          new DigestSpec("SHA256"),
          CodecSpec.HEX,
          new Object[] {
            CodecUtil.b64("7FHsteHnm6XQsJT1TTKbxw=="),
            CodecUtil.b64("ehp6PCnojSegFpRvStqQ9A=="),
          },
          3,
          "3a1edec6aef6d1736bec63130755690c07f04d7e7139d8fd685cc2d989961b79",
        },
      };
  }

  @DataProvider(name = "compare-data")
  public Object[][] getCompareData()
  {
    return
      new Object[][] {
        {
          new DigestSpec("SHA1"),
          CodecSpec.BASE64,
          "7fyOZXGp+gKMziV/2Px7RIMkxyI2O1H8",
          1,
          new Object[] {ByteUtil.toBytes("password"), },
        },
      };
  }


  @Test(dataProvider = "hash-data")
  public void testHash(
    final DigestSpec digest,
    final CodecSpec codec,
    final Object[] input,
    final int iterations,
    final String expected)
    throws Exception
  {
    final EncodingHashBean bean = new EncodingHashBean();
    bean.setDigestSpec(digest);
    bean.setCodecSpec(codec);
    bean.setIterations(iterations);
    assertEquals(bean.hash(input), expected);
  }


  @Test(dataProvider = "compare-data")
  public void testCompare(
    final DigestSpec digest,
    final CodecSpec codec,
    final String hash,
    final int iterations,
    final Object[] input)
    throws Exception
  {
    final EncodingHashBean bean = new EncodingHashBean();
    bean.setDigestSpec(digest);
    bean.setCodecSpec(codec);
    bean.setIterations(iterations);
    assertTrue(bean.compare(hash, input));
  }
}
