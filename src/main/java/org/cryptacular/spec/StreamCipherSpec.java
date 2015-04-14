/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.spec;

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
 * @author  Middleware Services
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


  @Override
  public String getAlgorithm()
  {
    return algorithm;
  }


  @Override
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


  @Override
  public String toString()
  {
    return algorithm;
  }
}
