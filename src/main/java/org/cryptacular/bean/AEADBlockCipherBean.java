/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.cryptacular.CiphertextHeader;
import org.cryptacular.adapter.AEADBlockCipherAdapter;
import org.cryptacular.generator.Nonce;
import org.cryptacular.spec.Spec;

/**
 * Cipher bean that performs encryption with a block cipher in AEAD mode (e.g. GCM, CCM).
 *
 * @author  Middleware Services
 */
public class AEADBlockCipherBean extends AbstractBlockCipherBean
{

  /** Mac size in bits. */
  public static final int MAC_SIZE_BITS = 128;

  /** AEAD block cipher specification (algorithm, mode, padding). */
  private Spec<AEADBlockCipher> blockCipherSpec;


  /** Creates a new instance. */
  public AEADBlockCipherBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  blockCipherSpec  Block cipher specification.
   * @param  keyStore  Key store containing encryption key.
   * @param  keyAlias  Name of encryption key entry in key store.
   * @param  keyPassword  Password used to decrypt key entry in keystore.
   * @param  nonce  Nonce/IV generator.
   */
  public AEADBlockCipherBean(
    final Spec<AEADBlockCipher> blockCipherSpec,
    final KeyStore keyStore,
    final String keyAlias,
    final String keyPassword,
    final Nonce nonce)
  {
    super(keyStore, keyAlias, keyPassword, nonce);
    setBlockCipherSpec(blockCipherSpec);
  }


  /** @return  Block cipher specification. */
  public Spec<AEADBlockCipher> getBlockCipherSpec()
  {
    return blockCipherSpec;
  }


  /**
   * Sets the AEAD block cipher specification.
   *
   * @param  blockCipherSpec  Describes a block cipher in terms of algorithm, mode, and padding.
   */
  public void setBlockCipherSpec(final Spec<AEADBlockCipher> blockCipherSpec)
  {
    this.blockCipherSpec = blockCipherSpec;
  }


  @Override
  public void encrypt(final InputStream input, final OutputStream output)
  {
    if (blockCipherSpec.toString().endsWith("CCM")) {
      throw new UnsupportedOperationException("CCM mode ciphers do not support chunked encryption.");
    }
    super.encrypt(input, output);
  }


  @Override
  public void decrypt(final InputStream input, final OutputStream output)
  {
    if (blockCipherSpec.toString().endsWith("CCM")) {
      throw new UnsupportedOperationException("CCM mode ciphers do not support chunked decryption.");
    }
    super.decrypt(input, output);
  }


  @Override
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
