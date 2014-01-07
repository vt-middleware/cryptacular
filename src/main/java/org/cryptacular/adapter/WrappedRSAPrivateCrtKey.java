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
import java.security.interfaces.RSAPrivateCrtKey;

import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * JCE/JDK RSA private key that wraps the corresponding BC RSA private key type, {@link RSAPrivateCrtKeyParameters}.
 *
 * @author Marvin S. Addison
 */
public class WrappedRSAPrivateCrtKey
  extends AbstractWrappedRSAKey<RSAPrivateCrtKeyParameters> implements RSAPrivateCrtKey
{
  /**
   * Creates a new instance that wraps the given BC RSA private key.
   *
   * @param  parameters  BC RSA private (certificate) key.
   */
  public WrappedRSAPrivateCrtKey(final RSAPrivateCrtKeyParameters parameters)
  {
    super(parameters);
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getPublicExponent()
  {
    return delegate.getPublicExponent();
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getPrimeP()
  {
    return delegate.getP();
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getPrimeQ()
  {
    return delegate.getQ();
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getPrimeExponentP()
  {
    return delegate.getDP();
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getPrimeExponentQ()
  {
    return delegate.getDQ();
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getCrtCoefficient()
  {
    return delegate.getQInv();
  }


  /** {@inheritDoc} */
  @Override
  public BigInteger getPrivateExponent()
  {
    return delegate.getExponent();
  }


}
