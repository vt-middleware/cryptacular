/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import javax.crypto.SecretKey;
import org.cryptacular.CiphertextHeader;
import org.cryptacular.CiphertextHeaderFactory;
import org.cryptacular.CryptoException;
import org.cryptacular.EncodingException;
import org.cryptacular.StreamException;
import org.cryptacular.V2CiphertextHeader;
import org.cryptacular.generator.Nonce;

/**
 * Base class for all cipher beans. The base class assumes all ciphertext output will contain a prepended {@link
 * V2CiphertextHeader} containing metadata that facilitates decryption.
 *
 * @author  Middleware Services
 */
public abstract class AbstractCipherBean implements CipherBean
{

  /** Keystore containing symmetric key(s). */
  private KeyStore keyStore;

  /** Keystore entry for alias of current key. */
  private String keyAlias;

  /** Password on private key entry. */
  private String keyPassword;

  /** Nonce generator. */
  private Nonce nonce;


  /** Creates a new instance. */
  public AbstractCipherBean() {}


  /**
   * Creates a new instance by specifying all properties.
   *
   * @param  keyStore  Key store containing encryption key.
   * @param  keyAlias  Name of encryption key entry in key store.
   * @param  keyPassword  Password used to decrypt key entry in keystore.
   * @param  nonce  Nonce/IV generator.
   */
  public AbstractCipherBean(final KeyStore keyStore, final String keyAlias, final String keyPassword, final Nonce nonce)
  {
    setKeyStore(keyStore);
    setKeyAlias(keyAlias);
    setKeyPassword(keyPassword);
    setNonce(nonce);
  }


  /** @return  Keystore that contains the {@link SecretKey}. */
  public KeyStore getKeyStore()
  {
    return keyStore;
  }


  /**
   * Sets the keystore containing encryption/decryption key(s). The keystore must contain a {@link SecretKey} entry
   * whose alias is given by {@link #setKeyAlias(String)}, which will be used at the encryption key. It may contain
   * additional symmetric keys to support, for example, key rollover where some existing ciphertexts have headers
   * specifying a different key. In general all keys used for outstanding ciphertexts should be contained in the
   * keystore.
   *
   * @param  keyStore  Keystore containing encryption key(s).
   */
  public void setKeyStore(final KeyStore keyStore)
  {
    this.keyStore = keyStore;
  }


  /** @return  Alias that specifies the {@link KeyStore} entry containing the {@link SecretKey}. */
  public String getKeyAlias()
  {
    return keyAlias;
  }


  /**
   * Sets the keystore entry alias used to locate the current encryption key.
   *
   * @param  keyAlias  Alias of {@link SecretKey} used for encryption.
   */
  public void setKeyAlias(final String keyAlias)
  {
    this.keyAlias = keyAlias;
  }


  /**
   * Sets the password used to access the encryption key.
   *
   * @param  keyPassword  Encryption key password.
   */
  public void setKeyPassword(final String keyPassword)
  {
    this.keyPassword = keyPassword;
  }


  /** @return  Nonce/IV generation strategy. */
  public Nonce getNonce()
  {
    return nonce;
  }


  /**
   * Sets the nonce/IV generation strategy.
   *
   * @param  nonce  Nonce generator.
   */
  public void setNonce(final Nonce nonce)
  {
    this.nonce = nonce;
  }


  @Override
  public byte[] encrypt(final byte[] input) throws CryptoException
  {
    return process(header(), true, input);
  }


  @Override
  public void encrypt(final InputStream input, final OutputStream output) throws CryptoException, StreamException
  {
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
    return process(CiphertextHeaderFactory.decode(input, this::lookupKey), false, input);
  }


  @Override
  public void decrypt(final InputStream input, final OutputStream output)
      throws CryptoException, EncodingException, StreamException
  {
    process(CiphertextHeaderFactory.decode(input, this::lookupKey), false, input, output);
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
    final V2CiphertextHeader header = new V2CiphertextHeader(nonce.generate(), keyAlias);
    header.setKeyLookup(this::lookupKey);
    return header;
  }
}
