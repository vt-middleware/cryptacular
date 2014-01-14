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

package org.cryptacular.bean;

import java.io.IOException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.cryptacular.io.Resource;
import org.cryptacular.util.StreamUtil;

/**
 * Factory that produces a {@link SecretKey} from a {@link Resource}.
 *
 * @author Marvin S. Addison
 */
public class ResourceBasedSecretKeyFactoryBean implements FactoryBean<SecretKey>
{
  /** Key algorithm. */
  private String algorithm;

  /** Resource containing key data. */
  private Resource resource;


  /** Creates a new instance. */
  public ResourceBasedSecretKeyFactoryBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  resource  Resource containing encoded key data.
   * @param  algorithm  Algorithm name of cipher with which key will be used.
   */
  public ResourceBasedSecretKeyFactoryBean(final Resource resource, final String algorithm)
  {
    setResource(resource);
    setAlgorithm(algorithm);
  }


  /**
   * @return  Key algorithm name, e.g. AES.
   */
  public String getAlgorithm()
  {
    return algorithm;
  }


  /**
   * Sets the key algorithm.
   *
   * @param  algorithm  Secret key algorithm, e.g. AES.
   */
  public void setAlgorithm(final String algorithm)
  {
    this.algorithm = algorithm;
  }


  /**
   * @return  Resource containing key data.
   */
  public Resource getResource()
  {
    return resource;
  }


  /**
   * Sets the resource containing key data.
   *
   * @param  resource  Resource containing key bytes.
   */
  public void setResource(final Resource resource)
  {
    this.resource = resource;
  }


  /** {@inheritDoc} */
  @Override
  public SecretKey newInstance()
  {
    try {
      return new SecretKeySpec(StreamUtil.readAll(resource.getInputStream()), algorithm);
    } catch (IOException e) {
      throw new RuntimeException("Error getting input stream from " + resource);
    }
  }
}
