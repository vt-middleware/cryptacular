/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.security.KeyStore;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.cryptacular.CiphertextHeader;
import org.cryptacular.CryptUtil;
import org.cryptacular.adapter.BufferedBlockCipherAdapter;
import org.cryptacular.generator.Nonce;
import org.cryptacular.spec.Spec;

/**
 * Cipher bean that performs symmetric encryption/decryption using a standard block cipher in a standard mode (e.g. CBC,
 * OFB) with padding to support processing inputs of arbitrary length.
 *
 * @author  Middleware Services
 */
public class BufferedBlockCipherBean extends AbstractBlockCipherBean
{

  /** Block cipher specification (algorithm, mode, padding). */
  private final Spec<BufferedBlockCipher> blockCipherSpec;


  /**
   * Creates a buffered block cipher bean.
   *
   * @param  blockCipherSpec  Block cipher specification.
   * @param  keyStore  Key store containing encryption key.
   * @param  keyAlias  Name of encryption key entry in key store.
   * @param  keyPassword  Password used to decrypt key entry in keystore.
   * @param  nonce  Nonce/IV generator.
   */
  public BufferedBlockCipherBean(
    final Spec<BufferedBlockCipher> blockCipherSpec,
    final KeyStore keyStore,
    final String keyAlias,
    final String keyPassword,
    final Nonce nonce)
  {
    super(keyStore, keyAlias, keyPassword, nonce);
    this.blockCipherSpec = CryptUtil.assertNotNullArg(blockCipherSpec, "Block cipher spec cannot be null");
  }


  /** @return  Block cipher specification. */
  public Spec<BufferedBlockCipher> getBlockCipherSpec()
  {
    return blockCipherSpec;
  }


  @Override
  protected BufferedBlockCipherAdapter newCipher(final CiphertextHeader header, final boolean mode)
  {
    final BufferedBlockCipher cipher = blockCipherSpec.newInstance();
    CipherParameters params = new KeyParameter(lookupKey(header.getKeyName()).getEncoded());
    final String algName = cipher.getUnderlyingCipher().getAlgorithmName();
    if (algName.endsWith("CBC") || algName.endsWith("OFB") || algName.endsWith("CFB")) {
      params = new ParametersWithIV(params, header.getNonce());
    }
    cipher.init(mode, params);
    return new BufferedBlockCipherAdapter(cipher);
  }
}
