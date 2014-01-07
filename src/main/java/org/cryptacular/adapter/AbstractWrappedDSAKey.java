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

package org.cryptacular.adapter;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;

import org.bouncycastle.crypto.params.DSAKeyParameters;

/**
 * Base class for DSA wrapped keys.
 *
 * @author Marvin S. Addison
 * @param  <T>  DSA key parameters type.
 */
public abstract class AbstractWrappedDSAKey<T extends DSAKeyParameters> extends AbstractWrappedKey<T>
{
  /** DSA algorithm name. */
  private static final String ALGORITHM = "DSA";


  /**
   * Creates a new instance that wraps the given key.
   *
   * @param  wrappedKey  Key to wrap.
   */
  public AbstractWrappedDSAKey(final T wrappedKey)
  {
    super(wrappedKey);
  }


  /**
   * @return  DSA key parameters.
   */
  public DSAParams getParams()
  {
    return new DSAParams()
    {
      @Override
      public BigInteger getP()
      {
        return delegate.getParameters().getP();
      }

      @Override
      public BigInteger getQ()
      {
        return delegate.getParameters().getQ();
      }

      @Override
      public BigInteger getG()
      {
        return delegate.getParameters().getG();
      }
    };
  }


  /** {@inheritDoc} */
  @Override
  public String getAlgorithm()
  {
    return ALGORITHM;
  }
}
