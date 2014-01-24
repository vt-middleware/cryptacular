/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

/**
 * Factory bean strategy interface.
 *
 * @param  <T>  Type produced by factory.
 *
 * @author  Middleware Services
 */
public interface FactoryBean<T>
{

  /** @return  New instance of the type handled by this factory. */
  T newInstance();
}
