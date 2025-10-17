/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.pbe;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.io.CipherInputStream;
import org.bouncycastle.crypto.io.CipherOutputStream;
import org.bouncycastle.util.io.Streams;
import org.cryptacular.CryptUtil;
import org.cryptacular.CryptoException;

/**
 * Abstract base class for password-based encryption schemes based on salt data and iterated hashing as the basis of the
 * key derivation function.
 *
 * <p>NOTE: Classes derived from this class are not thread safe. In particular, care should be taken to prevent multiple
 * threads from performing encryption and/or decryption concurrently.</p>
 *
 * @author  Middleware Services
 * @version  $Revision: 2744 $
 */
public abstract class AbstractEncryptionScheme implements EncryptionScheme
{

  /** Cipher used for encryption and decryption. */
  private BufferedBlockCipher cipher;

  /** Cipher initialization parameters. */
  private CipherParameters parameters;


  @Override
  public byte[] encrypt(final byte[] plaintext)
  {
    CryptUtil.assertNotNullArg(plaintext, "Plain text cannot be null");
    cipher.init(true, parameters);
    return process(plaintext);
  }


  @Override
  public void encrypt(final InputStream in, final OutputStream out)
    throws IOException
  {
    CryptUtil.assertNotNullArg(in, "Input stream cannot be null");
    CryptUtil.assertNotNullArg(out, "Output stream cannot be null");
    cipher.init(true, parameters);
    Streams.pipeAll(in, new CipherOutputStream(out, cipher));
  }


  @Override
  public byte[] decrypt(final byte[] ciphertext)
  {
    CryptUtil.assertNotNullArg(ciphertext, "Cipher text cannot be null");
    cipher.init(false, parameters);
    return process(ciphertext);
  }


  @Override
  public void decrypt(final InputStream in, final OutputStream out)
    throws IOException
  {
    CryptUtil.assertNotNullArg(in, "Input stream cannot be null");
    CryptUtil.assertNotNullArg(out, "Output stream cannot be null");
    cipher.init(false, parameters);
    Streams.pipeAll(new CipherInputStream(in, cipher), out);
  }


  @Override
  public OutputStream wrap(final boolean encryptionFlag, final OutputStream out)
  {
    CryptUtil.assertNotNullArg(out, "Output stream cannot be null");
    cipher.init(encryptionFlag, parameters);
    return new CipherOutputStream(out, cipher);
  }


  /**
   * Sets the block cipher used for encryption/decryption.
   *
   * @param  bufferedBlockCipher  Buffered block cipher.
   */
  protected void setCipher(final BufferedBlockCipher bufferedBlockCipher)
  {
    this.cipher = CryptUtil.assertNotNullArg(bufferedBlockCipher, "Block cipher cannot be null");
  }


  /**
   * Sets block cipher initialization parameters.
   *
   * @param  parameters  Cipher-specific init params.
   */
  protected void setCipherParameters(final CipherParameters parameters)
  {
    this.parameters = CryptUtil.assertNotNullArg(parameters, "Cipher parameters cannot be null");
  }


  /**
   * Run the given data through the initialized underlying cipher and return the result.
   *
   * @param  input  Input data.
   *
   * @return  Result of cipher acting on input.
   */
  private byte[] process(final byte[] input)
  {
    final byte[] output = new byte[cipher.getOutputSize(input.length)];
    int processed = cipher.processBytes(input, 0, input.length, output, 0);
    try {
      processed += cipher.doFinal(output, processed);
    } catch (InvalidCipherTextException e) {
      throw new CryptoException("Cipher error", e);
    }
    return Arrays.copyOfRange(output, 0, processed);
  }
}
