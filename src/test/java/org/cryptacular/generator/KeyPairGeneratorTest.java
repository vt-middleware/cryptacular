/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link KeyPairGenerator} class.
 *
 * @author  Middleware Services
 */
public class KeyPairGeneratorTest
{
  private final SecureRandom random = new SecureRandom();

  private Provider bc;

  @BeforeMethod
  public void registerProvider()
  {
    bc = new BouncyCastleProvider();
    Security.addProvider(bc);
  }

  @AfterMethod
  public void removeProvider()
  {
    Security.removeProvider("BC");
  }

  @DataProvider(name = "rsa-key-sizes")
  public Object[][] getRsaKeySizes()
  {
    return new Object[][] {
      new Object[] {1024},
      new Object[] {2048},
    };
  }

  @DataProvider(name = "dsa-key-sizes")
  public Object[][] getDsaKeySizes()
  {
    return new Object[][] {
      new Object[] {1024},
    };
  }

  @DataProvider(name = "ec-key-sizes")
  public Object[][] getEcKeySizes()
  {
    return new Object[][] {
      new Object[] {256},
      new Object[] {384},
    };
  }

  @DataProvider(name = "ec-named-curves")
  public Object[][] getEcNamedCurves()
  {
    return new Object[][] {
      new Object[] {"P-256"},
      new Object[] {"P-384"},
    };
  }

  @Test(dataProvider = "rsa-key-sizes")
  public void testGenerateRSA(final int bitLength)
  {
    final RSAPublicKey pub = (RSAPublicKey) KeyPairGenerator.generateRSA(random, bitLength).getPublic();
    assertThat(pub.getModulus().bitLength()).isEqualTo(bitLength);
  }

  @Test(dataProvider = "dsa-key-sizes")
  public void testGenerateDSA(final int bitLength)
  {
    final DSAPublicKey pub = (DSAPublicKey) KeyPairGenerator.generateDSA(random, bitLength).getPublic();
    assertThat(pub.getParams().getP().bitLength()).isEqualTo(bitLength);
  }

  @Test(dataProvider = "ec-key-sizes")
  public void testGenerateECByBitLength(final int bitLength)
  {
    final ECPublicKey pub = (ECPublicKey) KeyPairGenerator.generateEC(random, bitLength).getPublic();
    assertThat(pub.getParams().getCurve().getField().getFieldSize()).isEqualTo(bitLength);
  }

  @Test(dataProvider = "ec-named-curves")
  public void testGenerateECByNamedCurve(final String namedCurve)
  {
    assertThat(KeyPairGenerator.generateEC(random, namedCurve).getPublic()).isInstanceOf(ECPublicKey.class);
  }

  @Test
  public void testGenerateECInvalidCurveThrows()
  {
    assertThatThrownBy(() -> KeyPairGenerator.generateEC(random, "not-a-curve"))
      .isInstanceOf(IllegalArgumentException.class)
      .hasMessageContaining("Invalid EC curve");
  }
}
