/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import org.cryptacular.FailListener;
import org.cryptacular.spec.CodecSpec;
import org.cryptacular.spec.DigestSpec;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.CodecUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link EncodingHashBean}.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class EncodingHashBeanTest
{
  @DataProvider(name = "hash-data")
  public Object[][] getHashData()
  {
    return
      new Object[][] {
        {
          new EncodingHashBean(CodecSpec.BASE64, new DigestSpec("SHA1"), 1, false),
          new Object[] {
            CodecUtil.b64("7FHsteHnm6XQsJT1TTKbxw=="),
            CodecUtil.b64("ehp6PCnojSegFpRvStqQ9A=="),
          },
          "Oadnuuj7QsRPUuMBiu+dmlT6qzU=",
        },
        {
          new EncodingHashBean(CodecSpec.BASE64, new DigestSpec("SHA1"), 1, true),
          new Object[] {
            CodecUtil.b64("7FHsteHnm6XQsJT1TTKbxw=="),
            CodecUtil.b64("ehp6PCnojSegFpRvStqQ9A=="),
            CodecUtil.b64("/siCJIPstwM="),
          },
          "uRt+VlmPzfGOPjSGoZLTxpvd1dP+yIIkg+y3Aw==",
        },
        {
          new EncodingHashBean(CodecSpec.HEX, new DigestSpec("SHA256"), 3, false),
          new Object[] {
            CodecUtil.b64("7FHsteHnm6XQsJT1TTKbxw=="),
            CodecUtil.b64("ehp6PCnojSegFpRvStqQ9A=="),
          },
          "3a1edec6aef6d1736bec63130755690c07f04d7e7139d8fd685cc2d989961b79",
        },
        {
          new EncodingHashBean(CodecSpec.HEX, new DigestSpec("SHA256"), 3, true),
          new Object[] {
            CodecUtil.b64("7FHsteHnm6XQsJT1TTKbxw=="),
            CodecUtil.b64("ehp6PCnojSegFpRvStqQ9A=="),
            CodecUtil.b64("DH9M1lDibNU="),
          },
          "79f2868e7f72ed18cd67858e8ffe589c6090d696f7ff298e021faf5855fd41a10c7f4cd650e26cd5",
        },
      };
  }

  @DataProvider(name = "compare-data")
  public Object[][] getCompareData()
  {
    return
      new Object[][] {
        {
          new EncodingHashBean(CodecSpec.BASE64, new DigestSpec("SHA1"), 1, false),
          "7fyOZXGp+gKMziV/2Px7RIMkxyI2O1H8",
          new Object[] {ByteUtil.toBytes("password"), },
        },
        {
          new EncodingHashBean(CodecSpec.BASE64, new DigestSpec("SHA1"), 1, true),
          "lrb+YkKHqoGbFtxYd0B5567N6ZYwqwvWQwvoSg==",
          new Object[] {ByteUtil.toBytes("password"), },
        },
      };
  }


  @Test(dataProvider = "hash-data")
  public void testHash(final EncodingHashBean bean, final Object[] input, final String expected)
    throws Exception
  {
    assertThat(bean.hash(input)).isEqualTo(expected);
  }


  @Test(dataProvider = "compare-data")
  public void testCompare(final EncodingHashBean bean, final String hash, final Object[] input)
    throws Exception
  {
    assertThat(bean.compare(hash, input)).isTrue();
  }
}
