/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.function.Function;
import javax.crypto.SecretKey;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.cryptacular.CiphertextHeader;
import org.cryptacular.CiphertextHeaderV2;
import org.cryptacular.CryptoException;
import org.cryptacular.EncodingException;
import org.cryptacular.StreamException;
import org.cryptacular.adapter.AEADBlockCipherAdapter;
import org.cryptacular.adapter.BlockCipherAdapter;
import org.cryptacular.adapter.BufferedBlockCipherAdapter;
import org.cryptacular.generator.Nonce;

/**
 * Utility class that performs encryption and decryption operations using a block cipher.
 *
 * @author  Middleware Services
 */
public final class CipherUtil
{

  /** Mac size in bits. */
  private static final int MAC_SIZE_BITS = 128;

  /** Private constructor of utility class. */
  private CipherUtil() {}


  /**
   * Encrypts data using an AEAD cipher. A {@link CiphertextHeaderV2} is prepended to the resulting ciphertext and
   * used as AAD (Additional Authenticated Data) passed to the AEAD cipher.
   *
   * @param  cipher  AEAD cipher.
   * @param  key  Encryption key.
   * @param  nonce  Nonce generator.
   * @param  data  Plaintext data to be encrypted.
   *
   * @return  Concatenation of encoded {@link CiphertextHeaderV2} and encrypted data that completely fills the returned
   *          byte array.
   *
   * @throws  CryptoException  on encryption errors.
   */
  public static byte[] encrypt(final AEADBlockCipher cipher, final SecretKey key, final Nonce nonce, final byte[] data)
    throws CryptoException
  {
    final byte[] iv = nonce.generate();
    final byte[] header = new CiphertextHeaderV2(iv, "1").encode(key);
    cipher.init(true, new AEADParameters(new KeyParameter(key.getEncoded()), MAC_SIZE_BITS, iv, header));
    return encrypt(new AEADBlockCipherAdapter(cipher), header, data);
  }


  /**
   * Encrypts data using an AEAD cipher. A {@link CiphertextHeaderV2} is prepended to the resulting ciphertext and used
   * as AAD (Additional Authenticated Data) passed to the AEAD cipher.
   *
   * @param  cipher  AEAD cipher.
   * @param  key  Encryption key.
   * @param  nonce  Nonce generator.
   * @param  input  Input stream containing plaintext data.
   * @param  output  Output stream that receives a {@link CiphertextHeaderV2} followed by ciphertext data produced by
   *                 the AEAD cipher in encryption mode.
   *
   * @throws  CryptoException  on encryption errors.
   * @throws  StreamException  on IO errors.
   */
  public static void encrypt(
    final AEADBlockCipher cipher,
    final SecretKey key,
    final Nonce nonce,
    final InputStream input,
    final OutputStream output)
    throws CryptoException, StreamException
  {
    final byte[] iv = nonce.generate();
    final byte[] header = new CiphertextHeaderV2(iv, "1").encode(key);
    cipher.init(true, new AEADParameters(new KeyParameter(key.getEncoded()), MAC_SIZE_BITS, iv, header));
    writeHeader(header, output);
    process(new AEADBlockCipherAdapter(cipher), input, output);
  }


  /**
   * Decrypts data using an AEAD cipher.
   *
   * @param  cipher  AEAD cipher.
   * @param  key  Encryption key.
   * @param  data  Ciphertext data containing a prepended {@link CiphertextHeaderV2}. The header is treated as AAD input
   *               to the cipher that is verified during decryption.
   *
   * @return  Decrypted data that completely fills the returned byte array.
   *
   * @throws  CryptoException  on encryption errors.
   * @throws  EncodingException  on decoding cyphertext header.
   */
  public static byte[] decrypt(final AEADBlockCipher cipher, final SecretKey key, final byte[] data)
      throws CryptoException, EncodingException
  {
    final CiphertextHeader header = decodeHeader(data, String -> key);
    final byte[] nonce = header.getNonce();
    final byte[] hbytes = header.encode();
    cipher.init(false, new AEADParameters(new KeyParameter(key.getEncoded()), MAC_SIZE_BITS, nonce, hbytes));
    return decrypt(new AEADBlockCipherAdapter(cipher), data, header.getLength());
  }


  /**
   * Decrypts data using an AEAD cipher.
   *
   * @param  cipher  AEAD cipher.
   * @param  key  Encryption key.
   * @param  input  Input stream containing a {@link CiphertextHeaderV2} followed by ciphertext data. The header is
   *                treated as AAD input to the cipher that is verified during decryption.
   * @param  output  Output stream that receives plaintext produced by block cipher in decryption mode.
   *
   * @throws  CryptoException  on encryption errors.
   * @throws  EncodingException  on decoding cyphertext header.
   * @throws  StreamException  on IO errors.
   */
  public static void decrypt(
    final AEADBlockCipher cipher,
    final SecretKey key,
    final InputStream input,
    final OutputStream output)
    throws CryptoException, EncodingException, StreamException
  {
    final CiphertextHeader header = decodeHeader(input, String -> key);
    final byte[] nonce = header.getNonce();
    final byte[] hbytes = header.encode();
    cipher.init(false, new AEADParameters(new KeyParameter(key.getEncoded()), MAC_SIZE_BITS, nonce, hbytes));
    process(new AEADBlockCipherAdapter(cipher), input, output);
  }


  /**
   * Encrypts data using the given block cipher with PKCS5 padding. A {@link CiphertextHeaderV2} is prepended to the
   * resulting ciphertext.
   *
   * @param  cipher  Block cipher.
   * @param  key  Encryption key.
   * @param  nonce  IV generator. Callers must take care to ensure that the length of generated IVs is equal to the
   *                cipher block size.
   * @param  data  Plaintext data to be encrypted.
   *
   * @return  Concatenation of encoded {@link CiphertextHeaderV2} and encrypted data that completely fills the returned
   *          byte array.
   *
   * @throws  CryptoException  on encryption errors.
   */
  public static byte[] encrypt(final BlockCipher cipher, final SecretKey key, final Nonce nonce, final byte[] data)
    throws CryptoException
  {
    final byte[] iv = nonce.generate();
    final byte[] header = new CiphertextHeaderV2(iv, "1").encode(key);
    final PaddedBufferedBlockCipher padded = new PaddedBufferedBlockCipher(cipher, new PKCS7Padding());
    padded.init(true, new ParametersWithIV(new KeyParameter(key.getEncoded()), iv));
    return encrypt(new BufferedBlockCipherAdapter(padded), header, data);
  }


  /**
   * Encrypts data using the given block cipher with PKCS5 padding. A {@link CiphertextHeader} is prepended to the
   * resulting ciphertext.
   *
   * @param  cipher  Block cipher.
   * @param  key  Encryption key.
   * @param  nonce  IV generator. Callers must take care to ensure that the length of generated IVs is equal to the
   *                cipher block size.
   * @param  input  Input stream containing plaintext data.
   * @param  output  Output stream that receives ciphertext produced by block cipher in encryption mode.
   *
   * @throws  CryptoException  on encryption errors.
   * @throws  StreamException  on IO errors.
   */
  public static void encrypt(
    final BlockCipher cipher,
    final SecretKey key,
    final Nonce nonce,
    final InputStream input,
    final OutputStream output)
    throws CryptoException, StreamException
  {
    final byte[] iv = nonce.generate();
    final byte[] header = new CiphertextHeaderV2(iv, "1").encode(key);
    final PaddedBufferedBlockCipher padded = new PaddedBufferedBlockCipher(cipher, new PKCS7Padding());
    padded.init(true, new ParametersWithIV(new KeyParameter(key.getEncoded()), iv));
    writeHeader(header, output);
    process(new BufferedBlockCipherAdapter(padded), input, output);
  }


  /**
   * Decrypts data using the given block cipher with PKCS5 padding.
   *
   * @param  cipher  Block cipher.
   * @param  key  Encryption key.
   * @param  data  Ciphertext data containing a prepended {@link CiphertextHeader}.
   *
   * @return  Decrypted data that completely fills the returned byte array.
   *
   * @throws  CryptoException  on encryption errors.
   * @throws  EncodingException  on decoding cyphertext header.
   */
  public static byte[] decrypt(final BlockCipher cipher, final SecretKey key, final byte[] data)
    throws CryptoException, EncodingException
  {
    final CiphertextHeader header = decodeHeader(data, String -> key);
    final PaddedBufferedBlockCipher padded = new PaddedBufferedBlockCipher(cipher, new PKCS7Padding());
    padded.init(false, new ParametersWithIV(new KeyParameter(key.getEncoded()), header.getNonce()));
    return decrypt(new BufferedBlockCipherAdapter(padded), data, header.getLength());
  }


  /**
   * Decrypts data using the given block cipher with PKCS5 padding.
   *
   * @param  cipher  Block cipher.
   * @param  key  Encryption key.
   * @param  input  Input stream containing a {@link CiphertextHeader} followed by ciphertext data.
   * @param  output  Output stream that receives plaintext produced by block cipher in decryption mode.
   *
   * @throws  CryptoException  on encryption errors.
   * @throws  EncodingException  on decoding cyphertext header.
   * @throws  StreamException  on IO errors.
   */
  public static void decrypt(
    final BlockCipher cipher,
    final SecretKey key,
    final InputStream input,
    final OutputStream output)
    throws CryptoException, EncodingException, StreamException
  {
    final CiphertextHeader header = decodeHeader(input, String -> key);
    final PaddedBufferedBlockCipher padded = new PaddedBufferedBlockCipher(cipher, new PKCS7Padding());
    padded.init(false, new ParametersWithIV(new KeyParameter(key.getEncoded()), header.getNonce()));
    process(new BufferedBlockCipherAdapter(padded), input, output);
  }


  /**
   * Decodes the ciphertext header at the start of the given byte array.
   * Supports both original (deprecated) and v2 formats.
   *
   * @param  data  Ciphertext data with prepended header.
   * @param  keyLookup  Decryption key lookup function.
   *
   * @return  Ciphertext header instance.
   */
  public static CiphertextHeader decodeHeader(final byte[] data, final Function<String, SecretKey> keyLookup)
  {
    try {
      return CiphertextHeaderV2.decode(data, keyLookup);
    } catch (EncodingException e) {
      return CiphertextHeader.decode(data);
    }
  }


  /**
   * Decodes the ciphertext header at the start of the given input stream.
   * Supports both original (deprecated) and v2 formats.
   *
   * @param  in  Ciphertext stream that is positioned at the start of the ciphertext header.
   * @param  keyLookup  Decryption key lookup function.
   *
   * @return  Ciphertext header instance.
   */
  public static CiphertextHeader decodeHeader(final InputStream in, final Function<String, SecretKey> keyLookup)
  {
    CiphertextHeader header;
    try {
      // Mark the stream start position so we can try again with old format header
      if (in.markSupported()) {
        in.mark(4);
      }
      header = CiphertextHeaderV2.decode(in, keyLookup);
    } catch (EncodingException e) {
      try {
        in.reset();
      } catch (IOException ioe) {
        throw new StreamException("Stream error trying to process old header format: " + ioe.getMessage());
      }
      header = CiphertextHeader.decode(in);
    }
    return header;
  }


  /**
   * Encrypts the given data.
   *
   * @param  cipher  Adapter for either a block or AEAD cipher.
   * @param  header  Encoded ciphertext header.
   * @param  data  Plaintext data to encrypt.
   *
   * @return  Concatenation of encoded header and encrypted data that completely fills the returned byte array.
   */
  private static byte[] encrypt(final BlockCipherAdapter cipher, final byte[] header, final byte[] data)
  {
    final int outSize = header.length + cipher.getOutputSize(data.length);
    final byte[] output = new byte[outSize];
    System.arraycopy(header, 0, output, 0, header.length);

    int outOff = header.length;
    outOff += cipher.processBytes(data, 0, data.length, output, outOff);
    cipher.doFinal(output, outOff);
    cipher.reset();
    return output;
  }


  /**
   * Decrypts the given data.
   *
   * @param  cipher  Adapter for either a block or AEAD cipher.
   * @param  data  Ciphertext data containing prepended header bytes.
   * @param  inOff  Offset into ciphertext at which encrypted data starts (i.e. after header).
   *
   * @return  Decrypted data that completely fills the returned byte array.
   */
  private static byte[] decrypt(final BlockCipherAdapter cipher, final byte[] data, final int inOff)
  {
    final int len = data.length - inOff;
    final int outSize = cipher.getOutputSize(len);
    final byte[] output = new byte[outSize];
    int outOff = cipher.processBytes(data, inOff, len, output, 0);
    outOff += cipher.doFinal(output, outOff);
    cipher.reset();
    if (outOff < output.length) {
      final byte[] temp = new byte[outOff];
      System.arraycopy(output, 0, temp, 0, outOff);
      return temp;
    }
    return output;
  }


  /**
   * Performs encryption or decryption on the given input stream based on the underlying cipher mode and writes the
   * result to the given output stream.
   *
   * @param  cipher  Adapter for either a block or AEAD cipher.
   * @param  input  Input stream containing data to be processed by the cipher.
   * @param  output  Output stream that receives the output of the cipher acting on the input.
   */
  private static void process(final BlockCipherAdapter cipher, final InputStream input, final OutputStream output)
  {
    final int inSize = 1024;
    final int outSize = cipher.getOutputSize(inSize);
    final byte[] inBuf = new byte[inSize];
    final byte[] outBuf = new byte[outSize > inSize ? outSize : inSize];
    int readLen;
    int writeLen;
    try {
      while ((readLen = input.read(inBuf)) > 0) {
        writeLen = cipher.processBytes(inBuf, 0, readLen, outBuf, 0);
        output.write(outBuf, 0, writeLen);
      }
      writeLen = cipher.doFinal(outBuf, 0);
      output.write(outBuf, 0, writeLen);
    } catch (IOException e) {
      throw new StreamException(e);
    }
  }


  /**
   * Writes a ciphertext header to the output stream.
   *
   * @param  header  Ciphertext header bytes.
   * @param  output  Output stream.
   */
  private static void writeHeader(final byte[] header, final OutputStream output)
  {
    try {
      output.write(header, 0, header.length);
    } catch (IOException e) {
      throw new StreamException(e);
    }
  }

}
