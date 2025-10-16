/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import javax.crypto.SecretKey;
import org.cryptacular.CiphertextHeader;
import org.cryptacular.CryptUtil;
import org.cryptacular.CryptoException;
import org.cryptacular.EncodingException;
import org.cryptacular.StreamException;
import org.cryptacular.generator.Nonce;
import org.cryptacular.util.CipherUtil;

/**
 * Base class for all cipher beans. The base class assumes all ciphertext output will contain a prepended {@link
 * CiphertextHeader} containing metadata that facilitates decryption.
 *
 * @author  Middleware Services
 */
public abstract class AbstractCipherBean implements CipherBean
{

  /** Keystore containing symmetric key(s). */
  private final KeyStore keyStore;

  /** Keystore entry for alias of current key. */
  private final String keyAlias;

  /** Password on private key entry. */
  private final String keyPassword;

  /** Nonce generator. */
  private final Nonce nonce;


  /**
   * Creates a new abstract cipher bean. The keystore must contain a {@link SecretKey} entry whose alias is given by the
   * supplied alias, which will be used at the encryption key. It may contain additional symmetric keys to support, for
   * example, key rollover where some existing ciphertexts have headers specifying a different key. In general all keys
   * used for outstanding ciphertexts should be contained in the keystore.
   *
   * @param  keyStore  Key store containing encryption key.
   * @param  keyAlias  Name of encryption key entry in key store.
   * @param  keyPassword  Password used to decrypt key entry in keystore.
   * @param  nonce  Nonce/IV generator.
   */
  public AbstractCipherBean(final KeyStore keyStore, final String keyAlias, final String keyPassword, final Nonce nonce)
  {
    this.keyStore = CryptUtil.assertNotNullArg(keyStore, "Keystore cannot be null");
    this.keyAlias = keyAlias;
    this.keyPassword = keyPassword;
    this.nonce = nonce;
  }


  /** @return  Keystore that contains the {@link SecretKey}. */
  public KeyStore getKeyStore()
  {
    return keyStore;
  }


  /** @return  Alias that specifies the {@link KeyStore} entry containing the {@link SecretKey}. */
  public String getKeyAlias()
  {
    return keyAlias;
  }


  /** @return  Nonce/IV generation strategy. */
  public Nonce getNonce()
  {
    return nonce;
  }


  @Override
  public byte[] encrypt(final byte[] input) throws CryptoException
  {
    return process(header(), true, input);
  }


  @Override
  public void encrypt(final InputStream input, final OutputStream output) throws CryptoException, StreamException
  {
    CryptUtil.assertNotNullArg(input, "Input cannot be null");
    CryptUtil.assertNotNullArg(output, "Output cannot be null");
    final CiphertextHeader header = header();
    try {
      output.write(header.encode());
    } catch (IOException e) {
      throw new StreamException(e);
    }
    process(header, true, input, output);
  }


  @Override
  public byte[] decrypt(final byte[] input) throws CryptoException, EncodingException
  {
    return process(CipherUtil.decodeHeader(input, this::lookupKey), false, input);
  }


  @Override
  public void decrypt(final InputStream input, final OutputStream output)
      throws CryptoException, EncodingException, StreamException
  {
    process(CipherUtil.decodeHeader(input, this::lookupKey), false, input, output);
  }


  /**
   * Looks up secret key entry in the {@link #keyStore}.
   *
   * @param  alias  Name of secret key entry.
   *
   * @return  Secret key.
   */
  protected SecretKey lookupKey(final String alias)
  {
    final Key key;
    try {
      key = keyStore.getKey(alias, keyPassword.toCharArray());
    } catch (Exception e) {
      throw new CryptoException("Error accessing keystore entry " + alias, e);
    }
    if (key instanceof SecretKey) {
      return (SecretKey) key;
    }
    throw new CryptoException(alias + " is not a secret key");
  }


  /**
   * Processes the given data under the action of the cipher.
   *
   * @param  header  Ciphertext header.
   * @param  mode  True for encryption; false for decryption.
   * @param  input  Data to process by cipher.
   *
   * @return  Ciphertext data under encryption, plaintext data under decryption.
   */
  protected abstract byte[] process(CiphertextHeader header, boolean mode, byte[] input);


  /**
   * Processes the given data under the action of the cipher.
   *
   * @param  header  Ciphertext header.
   * @param  mode  True for encryption; false for decryption.
   * @param  input  Stream containing input data.
   * @param  output  Stream that receives output of cipher.
   */
  protected abstract void process(CiphertextHeader header, boolean mode, InputStream input, OutputStream output);


  /**
   * @return  New ciphertext header for a pending encryption or decryption operation performed by this instance.
   */
  private CiphertextHeader header()
  {
    return new CiphertextHeader(nonce.generate(), keyAlias, this::lookupKey);
  }
}
