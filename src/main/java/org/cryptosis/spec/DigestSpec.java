package org.cryptosis.spec;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.digests.MD2Digest;
import org.bouncycastle.crypto.digests.MD4Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.RIPEMD128Digest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.RIPEMD256Digest;
import org.bouncycastle.crypto.digests.RIPEMD320Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;

/**
 * Describes a message digest function by name and provides a means to create a new instance of the digest via the
 * {@link #newInstance()} method.
 *
 * @author Marvin S. Addison
 */
public class DigestSpec implements Spec<Digest>
{
  /** Digest algorithm name. */
  private final String algorithm;

  /** Requested size of variable-size hash algorithms, e.g. SHA-3. -1 for hashes with fixed size outputs. */
  private final int size;


  /**
   * Creates a new instance from the given algorithm name.
   *
   * @param  algName  Digest algorithm name.
   */
  public DigestSpec(final String algName)
  {
    if (algName == null) {
      throw new IllegalArgumentException("Algorithm name is required.");
    }
    this.algorithm = algName;
    this.size = -1;
  }


  /**
   * Constructor for digests that have variable output size, e.g. SHA3.
   *
   * @param  algName  Digest algorithm name.
   * @param  digestSize  Size of resultant digest in bits.
   */
  public DigestSpec(final String algName, final int digestSize)
  {
    if (algName == null) {
      throw new IllegalArgumentException("Algorithm name is required.");
    }
    this.algorithm = algName;
    if (digestSize < 0) {
      throw new IllegalArgumentException("Digest size must be positive.");
    }
    this.size = digestSize;
  }


  /** {@inheritDoc} */
  public String getAlgorithm()
  {
    return algorithm;
  }


  /**
   * @return  Size of digest output in bytes, or -1 if the digest does not support variable size output.
   */
  public int getSize()
  {
    return size;
  }


  /**
   * Creates a new digest instance.
   *
   * @return  Digest instance.
   */
  public Digest newInstance()
  {
    final Digest digest;
    if ("GOST3411".equalsIgnoreCase(algorithm)) {
      digest = new GOST3411Digest();
    } else if ("MD2".equalsIgnoreCase(algorithm)) {
      digest = new MD2Digest();
    } else if ("MD4".equalsIgnoreCase(algorithm)) {
      digest = new MD4Digest();
    } else if ("MD5".equalsIgnoreCase(algorithm)) {
      digest = new MD5Digest();
    } else if ("RIPEMD128".equalsIgnoreCase(algorithm) || "RIPEMD-128".equalsIgnoreCase(algorithm)) {
      digest = new RIPEMD128Digest();
    } else if ("RIPEMD160".equalsIgnoreCase(algorithm) || "RIPEMD-160".equalsIgnoreCase(algorithm)) {
      digest = new RIPEMD160Digest();
    } else if ("RIPEMD256".equalsIgnoreCase(algorithm) || "RIPEMD-256".equalsIgnoreCase(algorithm)) {
      digest = new RIPEMD256Digest();
    } else if ("RIPEMD320".equalsIgnoreCase(algorithm) || "RIPEMD-320".equalsIgnoreCase(algorithm)) {
      digest = new RIPEMD320Digest();
    } else if ("SHA1".equalsIgnoreCase(algorithm) || "SHA-1".equalsIgnoreCase(algorithm)) {
      digest = new SHA1Digest();
    } else if ("SHA224".equalsIgnoreCase(algorithm) || "SHA-224".equalsIgnoreCase(algorithm)) {
      digest = new SHA224Digest();
    } else if ("SHA256".equalsIgnoreCase(algorithm) || "SHA-256".equalsIgnoreCase(algorithm)) {
      digest = new SHA256Digest();
    } else if ("SHA384".equalsIgnoreCase(algorithm) || "SHA-384".equalsIgnoreCase(algorithm)) {
      digest = new SHA384Digest();
    } else if ("SHA512".equalsIgnoreCase(algorithm) || "SHA-512".equalsIgnoreCase(algorithm)) {
      digest = new SHA512Digest();
    } else if ("SHA3".equalsIgnoreCase(algorithm) || "SHA-3".equalsIgnoreCase(algorithm)) {
      digest = new SHA3Digest(size);
    } else if ("Tiger".equalsIgnoreCase(algorithm)) {
      digest = new TigerDigest();
    } else if ("Whirlpool".equalsIgnoreCase(algorithm)) {
      digest = new WhirlpoolDigest();
    } else {
      throw new IllegalStateException("Unsupported digest algorithm " + algorithm);
    }
    return digest;
  }


  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    return algorithm;
  }
}
