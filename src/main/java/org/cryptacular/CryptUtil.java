/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

import java.util.function.Predicate;

/**
 * Provides utility methods for this package.
 *
 * @author  Middleware Services
 */
public final class CryptUtil
{


  /** Default constructor. */
  private CryptUtil() {}


  /**
   * Parse the supplied value as an integer. Returns the default value if the predicate is not met or if the value
   * cannot be parsed.
   *
   * @param value to parse
   * @param require predicate to enforce
   * @param defaultValue to return if predicate is false
   *
   * @return parsed integer or default
   */
  public static int parseInt(final String value, final Predicate<Integer> require, final int defaultValue)
  {
    final int i;
    try {
      i = Integer.parseInt(value);
    } catch (NumberFormatException e) {
      return defaultValue;
    }
    return require.test(i) ? i : defaultValue;
  }


  /**
   * Throws {@link IllegalArgumentException} if the supplied object is null.
   *
   * @param  <T>  type of object
   * @param  o to check
   * @param  msg to include in the exception
   *
   * @return  supplied object
   */
  public static <T> T assertNotNullArg(final T o, final String msg)
  {
    if (o == null) {
      throw new IllegalArgumentException(msg);
    }
    return o;
  }


  /**
   * Throws {@link IllegalArgumentException} if the supplied object is null or the supplied predicate returns true.
   *
   * @param  <T>  type of object
   * @param  o to check
   * @param  predicate  to test
   * @param  msg to include in the exception
   *
   * @return  supplied object
   */
  public static <T> T assertNotNullArgOr(final T o, final Predicate<T> predicate, final String msg)
  {
    try {
      if (o == null || predicate.test(o)) {
        throw new IllegalArgumentException(msg);
      }
    } catch (Exception e) {
      // treat a predicate exception as an illegal argument
      throw new IllegalArgumentException(e);
    }
    return o;
  }
}
