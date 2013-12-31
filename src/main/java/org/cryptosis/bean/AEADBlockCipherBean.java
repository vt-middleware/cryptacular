package org.cryptosis.bean;

import java.io.InputStream;
import java.io.OutputStream;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.cryptosis.CiphertextHeader;
import org.cryptosis.bean.adapter.AEADBlockCipherAdapter;
import org.cryptosis.spec.Spec;

/**
 * Cipher bean that performs encryption with a block cipher in AEAD mode (e.g. GCM, CCM).
 *
 * @author Marvin S. Addison
 */
public class AEADBlockCipherBean extends AbstractBlockCipherBean
{
  /** Mac size in bits. */
  public static final int MAC_SIZE_BITS = 128;

  /** AEAD block cipher specification (algorithm, mode, padding). */
  private Spec<AEADBlockCipher> blockCipherSpec;


  /**
   * Sets the AEAD block cipher specification.
   *
   * @param  blockCipherSpec  Describes a block cipher in terms of algorithm, mode, and padding.
   */
  public void setBlockCipherSpec(final Spec<AEADBlockCipher> blockCipherSpec)
  {
    this.blockCipherSpec = blockCipherSpec;
  }


  /**
   * {@inheritDoc}
   */
  @Override
  public void encrypt(final InputStream input, final OutputStream output)
  {
    if (blockCipherSpec.toString().endsWith("CCM")) {
      throw new UnsupportedOperationException("CCM mode ciphers do not support chunked encryption.");
    }
    super.encrypt(input, output);
  }


  /**
   * {@inheritDoc}
   */
  @Override
  public void decrypt(final InputStream input, final OutputStream output)
  {
    if (blockCipherSpec.toString().endsWith("CCM")) {
      throw new UnsupportedOperationException("CCM mode ciphers do not support chunked decryption.");
    }
    super.decrypt(input, output);
  }


  /** {@inheritDoc} */
  protected AEADBlockCipherAdapter newCipher(final CiphertextHeader header, final boolean mode)
  {
    final AEADBlockCipher cipher = blockCipherSpec.newInstance();
    final SecretKey key = lookupKey(header.getKeyName());
    final AEADParameters params = new AEADParameters(
      new KeyParameter(key.getEncoded()),
      MAC_SIZE_BITS,
      header.getNonce(),
      header.encode());
    cipher.init(mode, params);
    return new AEADBlockCipherAdapter(cipher);
  }
}
