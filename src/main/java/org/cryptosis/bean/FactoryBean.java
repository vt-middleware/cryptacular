package org.cryptosis.bean;

/**
 * Factory bean strategy interface.
 *
 * @author Marvin S. Addison
 */
public interface FactoryBean<T>
{
  /**
   * @return  New instance of the type handled by this factory.
   */
  T newInstance();
}
