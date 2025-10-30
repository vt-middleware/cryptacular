/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.File;
import java.security.PublicKey;
import org.cryptacular.FailListener;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link PemBasedPublicKeyFactoryBean}.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class PemBasedPublicKeyFactoryBeanTest
{
  private static final String KEY_PATH = "src/test/resources/keys/";

  @DataProvider(name = "keys")
  public Object[][] getKeys()
  {
    return
      new Object[][] {
        new Object[] {KEY_PATH + "dsa-pub.pem"},
        new Object[] {KEY_PATH + "rsa-pub.pem"},
        new Object[] {KEY_PATH + "ec-secp224k1-explicit-pub.pem"},
      };
  }

  @Test(dataProvider = "keys")
  public void testNewInstance(final String path)
    throws Exception
  {
    final String pem = ByteUtil.toString(StreamUtil.readAll(new File(path)));
    final PemBasedPublicKeyFactoryBean factory = new PemBasedPublicKeyFactoryBean(pem);
    assertThat(factory.newInstance()).isInstanceOf(PublicKey.class);
  }
}
