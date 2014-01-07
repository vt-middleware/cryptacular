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

package org.cryptosis.spec;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.Grain128Engine;
import org.bouncycastle.crypto.engines.HC128Engine;
import org.bouncycastle.crypto.engines.HC256Engine;
import org.bouncycastle.crypto.engines.ISAACEngine;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.engines.Salsa20Engine;
import org.bouncycastle.crypto.engines.VMPCEngine;

/**
 * Stream cipher specification.
 *
 * @author Marvin S. Addison
 */
public class StreamCipherSpec implements Spec<StreamCipher>
{
  /** Cipher algorithm algorithm. */
  private final String algorithm;


  /**
   * Creates a new instance that describes the given stream cipher algorithm.
   *
   * @param  algName  Stream cipher algorithm.
   */
  public StreamCipherSpec(final String algName)
  {
    this.algorithm = algName;
  }


  /** {@inheritDoc} */
  public String getAlgorithm()
  {
    return algorithm;
  }


  /** {@inheritDoc} */
  public StreamCipher newInstance()
  {
    StreamCipher cipher;
    if ("Grainv1".equalsIgnoreCase(algorithm) || "Grain-v1".equalsIgnoreCase(algorithm)) {
      cipher = new ISAACEngine();
    } else if ("Grain128".equalsIgnoreCase(algorithm) || "Grain-128".equalsIgnoreCase(algorithm)) {
      cipher = new Grain128Engine();
    } else if ("ISAAC".equalsIgnoreCase(algorithm)) {
      cipher = new ISAACEngine();
    } else if ("HC128".equalsIgnoreCase(algorithm)) {
      cipher = new HC128Engine();
    } else if ("HC256".equalsIgnoreCase(algorithm)) {
      cipher = new HC256Engine();
    } else if ("RC4".equalsIgnoreCase(algorithm)) {
      cipher = new RC4Engine();
    } else if ("Salsa20".equalsIgnoreCase(algorithm)) {
      cipher = new Salsa20Engine();
    } else if ("VMPC".equalsIgnoreCase(algorithm)) {
      cipher = new VMPCEngine();
    } else {
      throw new IllegalStateException("Unsupported cipher algorithm " + algorithm);
    }
    return cipher;
  }


  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    return algorithm;
  }
}
