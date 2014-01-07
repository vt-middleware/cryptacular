/*
 * Licensed to Virginia Tech under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Virginia Tech licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.cryptacular.util;

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


  /**
   * Gets the method defined on the target class. The method is cached to speed up subsequent lookups.
   *
   * @param  target  Target class that contains method.
   * @param  name  Method name.
   * @param  parameters  Method parameters.
   *
   * @return  Method if found, otherwise null.
   */
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


  /**
   * Invokes the method on the target object with the given parameters.
   *
   * @param  target  Target class that contains method.
   * @param  method  Method to invoke on target.
   * @param  parameters  Method parameters.
   *
   * @return  Method return value. A void method returns null.
   */
  public static Object invoke(final Object target, final Method method, final Object ... parameters)
  {
    try {
      return method.invoke(target, parameters);
    } catch (Exception e) {
      throw new RuntimeException("Failed invoking " + method, e);
    }
  }
}
