package org.cryptosis.bean;

import org.cryptosis.spec.CodecSpec;
import org.cryptosis.spec.DigestSpec;
import org.cryptosis.util.ByteUtil;
import org.cryptosis.util.CodecUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link EncodingHashBean}.
 *
 * @author Marvin S. Addison
 */
public class EncodingHashBeanTest
{
  @DataProvider(name = "test-data" )
  public Object[][] getTestData()
  {
    return new Object[][] {
        new Object[] {
            ByteUtil.toBytes("Vilkommen"),
            new DigestSpec("SHA-256"),
            CodecSpec.BASE64,
            "Kmgr/A02GIvA6ztYHTw4IX/Pffwp3endHokKRjat2pM=" },
        new Object[] {
            CodecUtil.b64("gDu8UYjC0xP2YGpUtm9qEA=="),
            new DigestSpec("MD5"),
            CodecSpec.HEX,
            "e258a74f91e30662a42ccb5a8d904eed" },
    };
  }

  @Test(dataProvider = "test-data")
  public void testHash(
      final byte[] input, final DigestSpec digest, final CodecSpec codec, final String expected) throws Exception
  {
    final EncodingHashBean bean = new EncodingHashBean();
    bean.setDigestSpec(digest);
    bean.setCodecSpec(codec);
    assertEquals(bean.hash(input), expected);
  }
}
