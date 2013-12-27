package org.cryptosis.generator;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.cryptosis.spec.Spec;
import org.cryptosis.util.NonceUtil;

import javax.crypto.SecretKey;

/**
 * Nonce generation strategy that produces a random value according to NIST
 * <a href="http://goo.gl/S9z8qF">SP-800-63a</a>, appendix C, method 1 (encrypted nonce),
 * suitable for use with any block cipher mode described in that standard.
 * <p>
 * Instances of this class are thread safe.
 *
 * @author Marvin S. Addison
 */
public class EncryptedNonce implements Nonce
{
  /** Block cipher. */
  private BlockCipher cipher;

  /** Encryption key. */
  private SecretKey key;


  /**
   * Creates a new instance.
   *
   * @param  cipherSpec  Block cipher specification.
   * @param  key  Symmetric key.
   */
  public EncryptedNonce(final Spec<BlockCipher> cipherSpec, final SecretKey key)
  {
    this(cipherSpec.newInstance(), key);
  }


  /**
   * Creates a new instance.
   *
   * @param  cipher  Block cipher to use.
   * @param  key  Symmetric key.
   */
  public EncryptedNonce(final BlockCipher cipher, final SecretKey key)
  {
    this.cipher = cipher;
    this.key = key;
  }


  /** {@inheritDoc} */
  @Override
  public byte[] generate() throws LimitException
  {
    final byte[] result = new byte[cipher.getBlockSize()];
    final byte[] nonce = NonceUtil.timestampNonce(result.length);
    synchronized (cipher) {
      cipher.init(true, new KeyParameter(key.getEncoded()));
      cipher.processBlock(nonce, 0, result, 0);
      cipher.reset();
    }
    return result;
  }


  /** {@inheritDoc} */
  @Override
  public int getLength()
  {
    return cipher.getBlockSize();
  }
}
