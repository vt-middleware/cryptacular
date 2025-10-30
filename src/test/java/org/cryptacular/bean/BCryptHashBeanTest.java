/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit test for {@link BCryptHashBean} class.
 *
 * @author Middleware Services
 */
public class BCryptHashBeanTest
{
  @DataProvider(name = "hashes")
  public Object[][] getHashData()
  {
    return
      new Object[][] {
        {"password", "$2a$5$bvIG6Nmid91Mu9RcmmWZfO5HJIMCT8riNW0hEp8f6/FuA2/mHZFpe"},
        {"x", "$2a$12$w6IdiZTAckGirKaH8LU8VOxEvP97cFLEW5ePVJzhZilSa5c.V/uMK"},
        {"abcdefghijklmnopqrstuvwxyz", "$2a$6$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"},
        {"abcdefghijklmnopqrstuvwxyz", "$2a$8$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz."},
      };
  }

  @Test(dataProvider = "hashes")
  public void testHash(final String password, final String expected)
  {
    final BCryptHashBean.BCryptParameters params = new BCryptHashBean.BCryptParameters(expected);
    final String hash = new BCryptHashBean(params.getCost()).hash(params.getSalt(), password);
    assertThat(params.encode(hash)).isEqualTo(expected);
  }

  @Test(dataProvider = "hashes")
  public void testCompare(final String password, final String expected)
  {
    assertThat(new BCryptHashBean(10).compare(expected, password)).isTrue();
  }
}
