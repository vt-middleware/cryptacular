/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.File;
import java.security.PrivateKey;
import org.cryptacular.FailListener;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link PemBasedPrivateKeyFactoryBean}.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class PemBasedPrivateKeyFactoryBeanTest
{
  private static final String KEY_PATH = "src/test/resources/keys/";

  @DataProvider(name = "keys")
  public Object[][] getKeys()
  {
    return
      new Object[][] {
        new Object[] {KEY_PATH + "dsa-pkcs8-nopass.pem"},
        new Object[] {KEY_PATH + "dsa-openssl-nopass.pem"},
        new Object[] {KEY_PATH + "rsa-pkcs8-nopass.pem"},
        new Object[] {KEY_PATH + "rsa-openssl-nopass.pem"},
        new Object[] {KEY_PATH + "ec-openssl-sect571r1-explicit-nopass.pem"},
      };
  }

  @Test(dataProvider = "keys")
  public void testNewInstance(final String path)
    throws Exception
  {
    final String pem = ByteUtil.toString(StreamUtil.readAll(new File(path)));
    final PemBasedPrivateKeyFactoryBean factory = new PemBasedPrivateKeyFactoryBean(pem);
    assertThat(factory.newInstance()).isInstanceOf(PrivateKey.class);
  }
}
