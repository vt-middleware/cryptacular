/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.function.BiConsumer;
import java.util.function.Function;
import javax.crypto.SecretKey;
import org.cryptacular.util.ByteUtil;

/**
 * Static factory class that produces the correct instance of {@link CiphertextHeader} given a byte array or byte
 * stream that presumably contains an encoded ciphertext header.
 *
 * @author Middleware Services
 */
public final class CiphertextHeaderFactory
{
  /** Prevent instantiating this class. */
  private CiphertextHeaderFactory() {}


  /**
   * Decodes the ciphertext header at the start of the given byte array. Supports both v1 and v2 formats.
   *
   * @param  data  Ciphertext data with prepended header.
   * @param  keyLookup  Decryption key lookup function.
   *
   * @return  Ciphertext header instance.
   */
  public static CiphertextHeader decode(final byte[] data, final Function<String, SecretKey> keyLookup)
    throws EncodingException
  {
    try {
      return decodeV2(data, keyLookup);
    } catch (HeaderVersionException e) {
      return decodeV1(data);
    }
  }


  /**
   * Decodes the ciphertext header at the start of the given input stream. Supports both v1 and v2 formats.
   *
   * @param  input  Ciphertext stream that is positioned at the start of the ciphertext header.
   * @param  keyLookup  Decryption key lookup function.
   *
   * @return  Ciphertext header instance.
   */
  public static CiphertextHeader decode(final InputStream input, final Function<String, SecretKey> keyLookup)
    throws EncodingException, StreamException
  {
    V1CiphertextHeader header;
    try {
      // Mark the stream start position so we can try again with old format header
      if (input.markSupported()) {
        input.mark(4);
      }
      header = decodeV2(input, keyLookup);
    } catch (EncodingException e) {
      try {
        input.reset();
      } catch (IOException ioe) {
        throw new StreamException("Stream error trying to process old header format: " + ioe.getMessage());
      }
      header = decodeV1(input);
    }
    return header;
  }


  /**
   * Creates a header from encrypted data containing a cleartext header prepended to the start.
   *
   * @param  data  Encrypted data with prepended header data.
   * @param  keyLookup  Function used to look up the secret key from the symbolic key name in the header.
   *
   * @return  Decoded header.
   *
   * @throws  EncodingException  when ciphertext header cannot be decoded.
   */
  private static V2CiphertextHeader decodeV2(final byte[] data, final Function<String, SecretKey> keyLookup)
    throws EncodingException
  {
    final ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
    return decodeV2Internal(
      ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN),
      keyLookup,
      ByteBuffer -> bb.getInt(),
      ByteBuffer -> bb.get(),
      (ByteBuffer, output) -> bb.get(output));
  }


  /**
   * Creates a header from encrypted data containing a cleartext header prepended to the start.
   *
   * @param  input  Input stream that is positioned at the start of ciphertext header data.
   * @param  keyLookup  Function used to look up the secret key from the symbolic key name in the header.
   *
   * @return  Decoded header.
   *
   * @throws  EncodingException  when ciphertext header cannot be decoded.
   * @throws  StreamException  on stream IO errors.
   */
  private static V2CiphertextHeader decodeV2(final InputStream input, final Function<String, SecretKey> keyLookup)
    throws EncodingException, StreamException
  {
    return decodeV2Internal(
      input, keyLookup, ByteUtil::readInt, CiphertextHeaderFactory::readByte, CiphertextHeaderFactory::readInto);
  }


  /**
   * Internal header decoding routine.
   *
   * @param  <T>  Type of input source.
   * @param  source  Source of header data (input stream or byte buffer).
   * @param  keyLookup  Function to look up key from symbolic key name in header.
   * @param  readIntFn  Function that produces a 4-byte integer from the input source.
   * @param  readByteFn  Function that produces a byte from the input source.
   * @param  readBytesConsumer  Function that fills a byte array from the input source.
   *
   * @return  Decoded header.
   */
  private static <T> V2CiphertextHeader decodeV2Internal(
    final T source,
    final Function<String, SecretKey> keyLookup,
    final Function<T, Integer> readIntFn,
    final Function<T, Byte> readByteFn,
    final BiConsumer<T, byte[]> readBytesConsumer)
  {
    final SecretKey key;
    final String keyName;
    final byte[] nonce;
    final byte[] hmac;
    try {
      final int version = readIntFn.apply(source);
      if (version != V2CiphertextHeader.VERSION) {
        throw new HeaderVersionException("Unsupported ciphertext header version");
      }
      final ByteArrayOutputStream out = new ByteArrayOutputStream(100);
      byte b = 0;
      int count = 0;
      while ((b = readByteFn.apply(source)) != 0) {
        out.write(b);
        if (out.size() > V2CiphertextHeader.MAX_KEYNAME_LEN) {
          throw new EncodingException("Bad ciphertext header: maximum nonce length exceeded");
        }
        count++;
      }
      keyName = ByteUtil.toString(out.toByteArray(), 0, count);
      key = keyLookup.apply(keyName);
      if (key == null) {
        throw new IllegalStateException("Symbolic key name mentioned in header was not found");
      }
      final int nonceLen = ByteUtil.toInt(readByteFn.apply(source));
      nonce = new byte[nonceLen];
      readBytesConsumer.accept(source, nonce);
      hmac = new byte[V2CiphertextHeader.HMAC_SIZE];
      readBytesConsumer.accept(source, hmac);
    } catch (IndexOutOfBoundsException | BufferUnderflowException e) {
      throw new EncodingException("Bad ciphertext header");
    }
    final V2CiphertextHeader header = new V2CiphertextHeader(nonce, keyName);
    final byte[] encoded = header.encode(key);
    if (!arraysEqual(hmac, 0, encoded, encoded.length - V2CiphertextHeader.HMAC_SIZE, V2CiphertextHeader.HMAC_SIZE)) {
      throw new EncodingException("Ciphertext header HMAC verification failed");
    }
    header.setKeyLookup(keyLookup);
    return header;
  }

  /**
   * Creates a header from encrypted data containing a version 1 cleartext header prepended to the start.
   *
   * @param  data  Encrypted data with prepended header data.
   *
   * @return  Decoded header.
   *
   * @throws  EncodingException  when ciphertext header cannot be decoded.
   */
  private static V1CiphertextHeader decodeV1(final byte[] data) throws EncodingException
  {
    final ByteBuffer bb = ByteBuffer.wrap(data);
    bb.order(ByteOrder.BIG_ENDIAN);

    final int length = bb.getInt();
    if (length < 0) {
      throw new EncodingException("Bad ciphertext header");
    }

    final byte[] nonce;
    int nonceLen = 0;
    try {
      nonceLen = bb.getInt();
      if (nonceLen > V1CiphertextHeader.MAX_NONCE_LEN) {
        throw new EncodingException("Bad ciphertext header: maximum nonce length exceeded");
      }
      nonce = new byte[nonceLen];
      bb.get(nonce);
    } catch (IndexOutOfBoundsException | BufferUnderflowException e) {
      throw new EncodingException("Bad ciphertext header");
    }

    String keyName = null;
    if (length > nonce.length + 8) {
      final byte[] b;
      int keyLen = 0;
      try {
        keyLen = bb.getInt();
        if (keyLen > V1CiphertextHeader.MAX_KEYNAME_LEN) {
          throw new EncodingException("Bad ciphertext header: maximum key length exceeded");
        }
        b = new byte[keyLen];
        bb.get(b);
        keyName = new String(b);
      } catch (IndexOutOfBoundsException | BufferUnderflowException e) {
        throw new EncodingException("Bad ciphertext header");
      }
    }

    return new V1CiphertextHeader(nonce, keyName);
  }


  /**
   * Creates a header from encrypted data containing a version 1 cleartext header prepended to the start.
   *
   * @param  input  Input stream that is positioned at the start of ciphertext header data.
   *
   * @return  Decoded header.
   *
   * @throws  EncodingException  when ciphertext header cannot be decoded.
   * @throws  StreamException  on stream IO errors.
   */
  private static V1CiphertextHeader decodeV1(final InputStream input) throws EncodingException, StreamException
  {
    final int length = ByteUtil.readInt(input);
    if (length < 0) {
      throw new EncodingException("Bad ciphertext header");
    }

    final byte[] nonce;
    int nonceLen = 0;
    try {
      nonceLen = ByteUtil.readInt(input);
      if (nonceLen > V1CiphertextHeader.MAX_NONCE_LEN) {
        throw new EncodingException("Bad ciphertext header: maximum nonce size exceeded");
      }
      nonce = new byte[nonceLen];
      input.read(nonce);
    } catch (ArrayIndexOutOfBoundsException e) {
      throw new EncodingException("Bad ciphertext header");
    } catch (IOException e) {
      throw new StreamException(e);
    }

    String keyName = null;
    if (length > nonce.length + 8) {
      final byte[] b;
      int keyLen = 0;
      try {
        keyLen = ByteUtil.readInt(input);
        if (keyLen > V1CiphertextHeader.MAX_KEYNAME_LEN) {
          throw new EncodingException("Bad ciphertext header: maximum key length exceeded");
        }
        b = new byte[keyLen];
        input.read(b);
      } catch (ArrayIndexOutOfBoundsException e) {
        throw new EncodingException("Bad ciphertext header");
      } catch (IOException e) {
        throw new StreamException(e);
      }
      keyName = new String(b);
    }

    return new V1CiphertextHeader(nonce, keyName);
  }


  /**
   * Read <code>output.length</code> bytes from the input stream into the output buffer.
   *
   * @param  input  Input stream.
   * @param  output  Output buffer.
   *
   * @throws  StreamException  on stream IO errors.
   */
  private static void readInto(final InputStream input, final byte[] output)
  {
    try {
      input.read(output);
    } catch (IOException e) {
      throw new StreamException(e);
    }
  }


  /**
   * Read a single byte from the input stream.
   *
   * @param  input  Input stream.
   *
   * @return  Byte read from input stream.
   */
  private static byte readByte(final InputStream input)
  {
    try {
      return (byte) input.read();
    } catch (IOException e) {
      throw new StreamException(e);
    }
  }


  /**
   * Determines if two byte array ranges are equal bytewise.
   *
   * @param  a  First array to compare.
   * @param  aOff  Offset into first array.
   * @param  b  Second array to compare.
   * @param  bOff  Offset into second array.
   * @param  length  Number of bytes to compare.
   *
   * @return  True if every byte in the given range is equal, false otherwise.
   */
  private static boolean arraysEqual(final byte[] a, final int aOff, final byte[] b, final int bOff, final int length)
  {
    if (length + aOff > a.length || length + bOff > b.length) {
      return false;
    }
    for (int i = 0; i < length; i++) {
      if (a[i + aOff] != b[i + bOff]) {
        return false;
      }
    }
    return true;
  }
}
