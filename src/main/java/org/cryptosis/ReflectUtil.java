package org.cryptosis;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

/**
 * Reflection utilities.
 *
 * @author Marvin S. Addison
 */
public final class ReflectUtil
{
  /** Method cache. */
  private static final Map<String, Method> METHOD_CACHE = new HashMap<String, Method>();

  /** Private constructor of utility class. */
  private ReflectUtil() {}

  public static Method getMethod(final Class<?> target, final String name, final Class<?> ... parameters)
  {
    final String key = target.getName() + '.' + name;
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

  public static Object invoke(final Object target, final Method method, final Object ... parameters)
  {
    try {
      return method.invoke(target, parameters);
    } catch (Exception e) {
      throw new RuntimeException("Failed invoking " + method, e);
    }
  }
}
