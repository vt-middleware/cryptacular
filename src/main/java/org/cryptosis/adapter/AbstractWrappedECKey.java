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

package org.cryptosis.adapter;

import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;

/**
 * Base class for wrapped EC keys.
 *
 * @author Marvin S. Addison
 * @param  <T>  EC key parameters type.
 */
public abstract class AbstractWrappedECKey<T extends ECKeyParameters> extends AbstractWrappedKey<T>
{
  /** Elliptic curve algorithm name. */
  private static final String ALGORITHM = "EC";


  /**
   * Creates a new instance that wraps the given key.
   *
   * @param  wrappedKey  Key to wrap.
   */
  public AbstractWrappedECKey(final T wrappedKey)
  {
    super(wrappedKey);
  }


  /** @return  EC domain parameters. */
  public ECParameterSpec getParams()
  {
    final ECDomainParameters params = delegate.getParameters();
    return new ECParameterSpec(
      EC5Util.convertCurve(params.getCurve(), params.getSeed()),
      new ECPoint(
        params.getG().getX().toBigInteger(),
        params.getG().getY().toBigInteger()),
      params.getN(),
      params.getH().intValue());
  }


  /** {@inheritDoc} */
  @Override
  public String getAlgorithm()
  {
    return ALGORITHM;
  }
}
