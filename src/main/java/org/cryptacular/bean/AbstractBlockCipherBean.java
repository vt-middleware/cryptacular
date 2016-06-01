/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import org.cryptacular.CiphertextHeader;
import org.cryptacular.StreamException;
import org.cryptacular.adapter.BlockCipherAdapter;
import org.cryptacular.generator.Nonce;
import org.cryptacular.util.StreamUtil;

/**
 * Base class for all cipher beans that use block cipher.
 *
 * @author  Middleware Services
 */
public abstract class AbstractBlockCipherBean extends AbstractCipherBean
{

  /** Creates a new instance. */
  public AbstractBlockCipherBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  keyStore  Key store containing encryption key.
   * @param  keyAlias  Name of encryption key entry in key store.
   * @param  keyPassword  Password used to decrypt key entry in keystore.
   * @param  nonce  Nonce/IV generator.
   */
  public AbstractBlockCipherBean(
    final KeyStore keyStore,
    final String keyAlias,
    final String keyPassword,
    final Nonce nonce)
  {
    super(keyStore, keyAlias, keyPassword, nonce);
  }


  @Override
  protected byte[] process(final CiphertextHeader header, final boolean mode, final byte[] input)
  {
    final BlockCipherAdapter cipher = newCipher(header, mode);
    final byte[] headerBytes = header.encode();
    int outOff;
    final int inOff;
    final int length;
    final byte[] output;
    if (mode) {
      final int outSize = headerBytes.length + cipher.getOutputSize(input.length);
      output = new byte[outSize];
      System.arraycopy(headerBytes, 0, output, 0, headerBytes.length);
      inOff = 0;
      outOff = headerBytes.length;
      length = input.length;
    } else {
      length = input.length - headerBytes.length;

      final int outSize = cipher.getOutputSize(length);
      output = new byte[outSize];
      inOff = headerBytes.length;
      outOff = 0;
    }
    outOff += cipher.processBytes(input, inOff, length, output, outOff);
    outOff += cipher.doFinal(output, outOff);
    if (outOff < output.length) {
      final byte[] copy = new byte[outOff];
      System.arraycopy(output, 0, copy, 0, outOff);
      return copy;
    }
    return output;
  }


  @Override
  protected void process(
    final CiphertextHeader header,
    final boolean mode,
    final InputStream input,
    final OutputStream output)
  {
    final BlockCipherAdapter cipher = newCipher(header, mode);
    final int outSize = cipher.getOutputSize(StreamUtil.CHUNK_SIZE);
    final byte[] outBuf = new byte[outSize > StreamUtil.CHUNK_SIZE ? outSize : StreamUtil.CHUNK_SIZE];
    StreamUtil.pipeAll(
      input,
      output,
      (in, inOff, len, out) -> {
        final int n = cipher.processBytes(in, inOff, len, outBuf, 0);
        out.write(outBuf, 0, n);
      });

    final int n = cipher.doFinal(outBuf, 0);
    try {
      output.write(outBuf, 0, n);
    } catch (IOException e) {
      throw new StreamException(e);
    }
  }


  /**
   * Creates a new cipher adapter instance suitable for the block cipher used by this class.
   *
   * @param  header  Ciphertext header.
   * @param  mode  True for encryption; false for decryption.
   *
   * @return  Block cipher adapter that wraps an initialized block cipher that is ready for use in the given mode.
   */
  protected abstract BlockCipherAdapter newCipher(CiphertextHeader header, boolean mode);
}
