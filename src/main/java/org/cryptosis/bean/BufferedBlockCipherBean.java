package org.cryptosis.bean;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.cryptosis.CiphertextHeader;
import org.cryptosis.bean.adapter.BufferedBlockCipherAdapter;
import org.cryptosis.spec.BufferedBlockCipherSpec;
import org.cryptosis.spec.Spec;

import javax.crypto.SecretKey;

/**
 * Cipher bean that performs symmetric encryption/decryption using a standard block cipher in a standard mode
 * (e.g. CBC, OFB) with padding to support processing inputs of arbitrary length.
 *
 * @author Marvin S. Addison
 */
public class BufferedBlockCipherBean extends AbstractBlockCipherBean
{
  /** Block cipher specification (algorithm, mode, padding). */
  private Spec<BufferedBlockCipher> blockCipherSpec;


  /**
   * Sets the block cipher specification.
   *
   * @param  blockCipherSpec  Describes a block cipher in terms of algorithm, mode, and padding.
   */
  public void setBlockCipherSpec(final Spec<BufferedBlockCipher> blockCipherSpec)
  {
    this.blockCipherSpec = blockCipherSpec;
  }


  /** {@inheritDoc} */
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
