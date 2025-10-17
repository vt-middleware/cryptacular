/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import org.cryptacular.CryptUtil;

/**
 * Reflection utilities.
 *
 * @author  Middleware Services
 */
public final class ReflectUtil
{

  /** Method cache. */
  private static final Map<String, Method> METHOD_CACHE = new HashMap<>();

  /** Private constructor of utility class. */
  private ReflectUtil() {}


  /**
   * Gets the method defined on the target class. The method is cached to speed up subsequent lookups.
   *
   * @param  target  Target class that contains method.
   * @param  name  Method name.
   * @param  parameters  Method parameters.
   *
   * @return  Method if found, otherwise null.
   */
  public static Method getMethod(final Class<?> target, final String name, final Class<?>... parameters)
  {
    CryptUtil.assertNotNullArg(target, "Target cannot be null");
    CryptUtil.assertNotNullArg(name, "Name cannot be null");
    final String key = target.getName() + '.' + name;
    synchronized (METHOD_CACHE) {
      Method method = METHOD_CACHE.get(key);
      if (method != null) {
        return method;
      }
      try {
        method = target.getMethod(name, parameters);
        METHOD_CACHE.put(key, method);
        return method;
      } catch (NoSuchMethodException e) {
        return null;
      }
    }
  }


  /**
   * Invokes the method on the target object with the given parameters.
   *
   * @param  target  Target class that contains method.
   * @param  method  Method to invoke on target.
   * @param  parameters  Method parameters.
   *
   * @return  Method return value. A void method returns null.
   */
  public static Object invoke(final Object target, final Method method, final Object... parameters)
  {
    CryptUtil.assertNotNullArg(target, "Target cannot be null");
    CryptUtil.assertNotNullArg(method, "Method cannot be null");
    try {
      return method.invoke(target, parameters);
    } catch (Exception e) {
      throw new RuntimeException("Failed invoking " + method, e);
    }
  }
}
