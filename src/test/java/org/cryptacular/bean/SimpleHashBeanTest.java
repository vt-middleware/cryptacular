/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import org.cryptacular.FailListener;
import org.cryptacular.spec.DigestSpec;
import org.cryptacular.util.CodecUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link SimpleHashBean}.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class SimpleHashBeanTest
{
  @DataProvider(name = "test-data")
  public Object[][] getTestData()
  {
    return
      new Object[][] {
        {
          new DigestSpec("SHA1"),
          new Object[] {
            CodecUtil.b64("7FHsteHnm6XQsJT1TTKbxw=="),
            CodecUtil.b64("ehp6PCnojSegFpRvStqQ9A=="),
          },
          1,
          "Oadnuuj7QsRPUuMBiu+dmlT6qzU=",
        },
        {
          new DigestSpec("SHA256"),
          new Object[] {
            CodecUtil.b64("7FHsteHnm6XQsJT1TTKbxw=="),
            CodecUtil.b64("ehp6PCnojSegFpRvStqQ9A=="),
          },
          3,
          "Oh7exq720XNr7GMTB1VpDAfwTX5xOdj9aFzC2YmWG3k=",
        },
      };
  }

  @Test(dataProvider = "test-data")
  public void testHash(final DigestSpec digest, final Object[] input, final int iterations, final String expectedBase64)
    throws Exception
  {
    final SimpleHashBean bean = new SimpleHashBean(digest, iterations);
    assertThat(CodecUtil.b64(bean.hash(input))).isEqualTo(expectedBase64);
  }
}
