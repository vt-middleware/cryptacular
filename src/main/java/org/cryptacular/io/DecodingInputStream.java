/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import org.cryptacular.CryptUtil;
import org.cryptacular.codec.Base64Decoder;
import org.cryptacular.codec.Decoder;
import org.cryptacular.codec.HexDecoder;

/**
 * Filters read bytes through a {@link Decoder} such that consumers obtain raw (decoded) bytes from read operations.
 *
 * @author  Middleware Services
 */
public class DecodingInputStream extends FilterInputStream
{

  /** Performs decoding. */
  private final Decoder decoder;

  /** Wraps the input stream to convert bytes to characters. */
  private final InputStreamReader reader;

  /** Holds input bytes as characters. */
  private CharBuffer input;

  /** Receives decoding result. */
  private ByteBuffer output;


  /**
   * Creates a new instance that wraps the given stream and performs decoding using the given encoder component.
   *
   * @param  in  Input stream to wrap.
   * @param  d  Decoder that provides on-the-fly decoding.
   */
  public DecodingInputStream(final InputStream in, final Decoder d)
  {
    super(CryptUtil.assertNotNullArg(in, "Input stream cannot be null"));
    decoder = CryptUtil.assertNotNullArg(d,  "Decoder cannot be null");
    reader = new InputStreamReader(in);
  }


  @Override
  public int read()
    throws IOException
  {
    return read(new byte[1]);
  }


  @Override
  public int read(final byte[] b)
    throws IOException
  {
    CryptUtil.assertNotNullArg(b, "Input byte array cannot be null");
    return read(b, 0, b.length);
  }


  @Override
  public int read(final byte[] b, final int off, final int len)
    throws IOException
  {
    CryptUtil.assertNotNullArg(b, "Input byte array cannot be null");
    prepareInputBuffer(len - off);
    prepareOutputBuffer();
    if (reader.read(input) < 0) {
      decoder.finalize(output);
      if (output.position() == 0) {
        return -1;
      }
    } else {
      input.flip();
      decoder.decode(input, output);
    }
    output.flip();
    output.get(b, off, output.limit());
    return output.position();
  }


  /**
   * Creates a new instance that decodes base64 input from the given stream.
   *
   * @param  in  Wrapped input stream.
   *
   * @return  Decoding input stream that decodes base64 output.
   */
  public static DecodingInputStream base64(final InputStream in)
  {
    return new DecodingInputStream(in, new Base64Decoder());
  }


  /**
   * Creates a new instance that decodes hexadecimal input from the given stream.
   *
   * @param  in  Wrapped input stream.
   *
   * @return  Decoding input stream that decodes hexadecimal output.
   */
  public static DecodingInputStream hex(final InputStream in)
  {
    return new DecodingInputStream(in, new HexDecoder());
  }


  /**
   * Prepares the input buffer to receive the given number of bytes.
   *
   * @param  required  Number of bytes required.
   */
  private void prepareInputBuffer(final int required)
  {
    if (input == null || input.capacity() < required) {
      input = CharBuffer.allocate(required);
    } else {
      input.clear();
    }
  }


  /** Prepares the output buffer based on input buffer capacity. */
  private void prepareOutputBuffer()
  {
    final int required = decoder.outputSize(input.capacity());
    if (output == null || output.capacity() < required) {
      output = ByteBuffer.allocate(required);
    } else {
      output.clear();
    }
  }
}
