/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.generator.sp80038a;

import javax.crypto.SecretKey;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.cryptacular.CryptUtil;
import org.cryptacular.generator.LimitException;
import org.cryptacular.generator.Nonce;
import org.cryptacular.spec.Spec;
import org.cryptacular.util.NonceUtil;

/**
 * Nonce generation strategy that produces a random value according to NIST <a href="http://goo.gl/S9z8qF">
 * SP-800-38a</a>, appendix C, method 1 (encrypted nonce), suitable for use with any block cipher mode described in that
 * standard except OFB.
 *
 * <p>Instances of this class are thread safe.</p>
 *
 * @author  Middleware Services
 */
public class EncryptedNonce implements Nonce
{

  /** Block cipher. */
  private final BlockCipher cipher;

  /** Encryption key. */
  private final SecretKey key;


  /**
   * Creates a new instance.
   *
   * @param  cipherSpec  Block cipher specification.
   * @param  key  Symmetric key.
   */
  public EncryptedNonce(final Spec<BlockCipher> cipherSpec, final SecretKey key)
  {
    this(CryptUtil.assertNotNullArg(cipherSpec, "Cipher spec cannot be null").newInstance(), key);
  }


  /**
   * Creates a new instance.
   *
   * @param  cipher  Block cipher to use.
   * @param  key  Symmetric key.
   */
  public EncryptedNonce(final BlockCipher cipher, final SecretKey key)
  {
    this.cipher = CryptUtil.assertNotNullArg(cipher, "Cipher cannot be null");
    this.key = CryptUtil.assertNotNullArgOr(key, v -> v.getEncoded().length == 0, "Secret key cannot be empty");
  }


  @Override
  public byte[] generate()
    throws LimitException
  {
    final byte[] result = new byte[cipher.getBlockSize()];
    final byte[] nonce = NonceUtil.randomNonce(result.length);
    synchronized (cipher) {
      try {
        cipher.init(true, new KeyParameter(key.getEncoded()));
        cipher.processBlock(nonce, 0, result, 0);
        cipher.reset();
      } catch (ArrayIndexOutOfBoundsException e) {
        throw new LimitException(e);
      }
    }
    return result;
  }


  @Override
  public int getLength()
  {
    return cipher.getBlockSize();
  }
}
