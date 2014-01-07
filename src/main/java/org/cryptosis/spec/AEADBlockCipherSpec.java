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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.CCMBlockCipher;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OCBBlockCipher;

/**
 * Describes an AEAD block cipher in terms of a (algorithm, mode) tuple and provides a facility to create a
 * new instance of the cipher via the {@link #newInstance()} method.
 *
 * @author  Middleware Services
 * @version  $Revision: 2744 $
 */
public class AEADBlockCipherSpec implements Spec<AEADBlockCipher>
{
  /** String specification format, <code>algorithm/mode</code>. */
  public static final Pattern FORMAT = Pattern.compile("(?<alg>[A-Za-z0-9_-]+)/(?<mode>\\w+)");

  /** Cipher algorithm algorithm. */
  private final String algorithm;

  /** Cipher mode, e.g. GCM, CCM. */
  private final String mode;


  /**
   * Creates a new instance from a cipher algorithm and mode.
   *
   * @param  algName  Cipher algorithm name.
   * @param  cipherMode  Cipher mode, e.g. GCM, CCM.
   */
  public AEADBlockCipherSpec(final String algName, final String cipherMode)
  {
    this.algorithm = algName;
    this.mode = cipherMode;
  }


  /** {@inheritDoc} */
  public String getAlgorithm()
  {
    return algorithm;
  }


  /**
   * Gets the cipher mode.
   *
   * @return  Cipher mode, e.g. CBC, OFB.
   */
  public String getMode()
  {
    return mode;
  }


  /**
   * Creates a new AEAD block cipher from the specification in this instance.
   *
   * @return  New AEAD block cipher instance.
   */
  public AEADBlockCipher newInstance()
  {
    final BlockCipher blockCipher = new BlockCipherSpec(algorithm).newInstance();
    AEADBlockCipher aeadBlockCipher;
    if ("GCM".equals(mode)) {
      aeadBlockCipher = new GCMBlockCipher(blockCipher);
    } else if ("CCM".equals(mode)) {
      aeadBlockCipher = new CCMBlockCipher(blockCipher);
    } else if ("OCB".equals(mode)) {
      aeadBlockCipher = new OCBBlockCipher(blockCipher, new BlockCipherSpec(algorithm).newInstance());
    } else if ("EAX".equals(mode)) {
      aeadBlockCipher = new EAXBlockCipher(blockCipher);
    } else {
      throw new IllegalStateException("Unsupported mode " + mode);
    }
    return aeadBlockCipher;
  }


  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    return algorithm + '/' + mode;
  }


  /**
   * Parses a string representation of a AEAD block cipher specification into an instance of this class.
   *
   * @param  specification  AEAD block cipher specification of the form <code>algorithm/mode</code>.
   *
   * @return  Buffered block cipher specification instance.
   */
  public static AEADBlockCipherSpec parse(final String specification)
  {
    final Matcher m = FORMAT.matcher(specification);
    if (!m.matches()) {
      throw new IllegalArgumentException("Invalid specification " + specification);
    }
    return new AEADBlockCipherSpec(m.group("alg"), m.group("mode"));
  }
}
