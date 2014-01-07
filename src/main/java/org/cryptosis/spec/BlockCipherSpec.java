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

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.CAST5Engine;
import org.bouncycastle.crypto.engines.CAST6Engine;
import org.bouncycastle.crypto.engines.CamelliaEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.GOST28147Engine;
import org.bouncycastle.crypto.engines.NoekeonEngine;
import org.bouncycastle.crypto.engines.RC2Engine;
import org.bouncycastle.crypto.engines.RC564Engine;
import org.bouncycastle.crypto.engines.RC6Engine;
import org.bouncycastle.crypto.engines.SEEDEngine;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.engines.SkipjackEngine;
import org.bouncycastle.crypto.engines.TEAEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.engines.XTEAEngine;

/**
 * Block cipher specification.
 *
 * @author Marvin S. Addison
 */
public class BlockCipherSpec implements Spec<BlockCipher>
{
  /** Cipher algorithm algorithm. */
  private final String algorithm;


  /**
   * Creates a new instance that describes the given block cipher algorithm.
   *
   * @param  algName  Block cipher algorithm.
   */
  public BlockCipherSpec(final String algName)
  {
    this.algorithm = algName;
  }


  /** {@inheritDoc} */
  public String getAlgorithm()
  {
    return algorithm;
  }


  /** {@inheritDoc} */
  public BlockCipher newInstance()
  {
    BlockCipher cipher;
    if ("AES".equalsIgnoreCase(algorithm)) {
      cipher = new AESFastEngine();
    } else if ("Blowfish".equalsIgnoreCase(algorithm)) {
      cipher = new BlowfishEngine();
    } else if ("Camellia".equalsIgnoreCase(algorithm)) {
      cipher = new CamelliaEngine();
    } else if ("CAST5".equalsIgnoreCase(algorithm)) {
      cipher = new CAST5Engine();
    } else if ("CAST6".equalsIgnoreCase(algorithm)) {
      cipher = new CAST6Engine();
    } else if ("DES".equalsIgnoreCase(algorithm)) {
      cipher = new DESEngine();
    } else if ("DESede".equalsIgnoreCase(algorithm) || "DES3".equalsIgnoreCase(algorithm)) {
      cipher = new DESedeEngine();
    } else if ("GOST".equalsIgnoreCase(algorithm) || "GOST28147".equals(algorithm)) {
      cipher = new GOST28147Engine();
    } else if ("Noekeon".equalsIgnoreCase(algorithm)) {
      cipher = new NoekeonEngine();
    } else if ("RC2".equalsIgnoreCase(algorithm)) {
      cipher = new RC2Engine();
    } else if ("RC5".equalsIgnoreCase(algorithm)) {
      cipher = new RC564Engine();
    } else if ("RC6".equalsIgnoreCase(algorithm)) {
      cipher = new RC6Engine();
    } else if ("SEED".equalsIgnoreCase(algorithm)) {
      cipher = new SEEDEngine();
    } else if ("Serpent".equalsIgnoreCase(algorithm)) {
      cipher = new SerpentEngine();
    } else if ("Skipjack".equalsIgnoreCase(algorithm)) {
      cipher = new SkipjackEngine();
    } else if ("TEA".equalsIgnoreCase(algorithm)) {
      cipher = new TEAEngine();
    } else if ("Twofish".equalsIgnoreCase(algorithm)) {
      cipher = new TwofishEngine();
    } else if ("XTEA".equalsIgnoreCase(algorithm)) {
      cipher = new XTEAEngine();
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
