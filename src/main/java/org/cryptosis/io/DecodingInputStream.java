package org.cryptosis.io;

import org.cryptosis.codec.Base64Decoder;
import org.cryptosis.codec.Decoder;
import org.cryptosis.codec.HexDecoder;

import java.io.FilterInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * Filters read bytes through a {@link Decoder} such that consumers obtain raw (decoded) bytes from read operations.
 *
 * @author Marvin S. Addison
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
    super(in);
    if (d == null) {
      throw new IllegalArgumentException("Decoder cannot be null.");
    }
    this.decoder = d;
    this.reader = new InputStreamReader(in);
  }


  /** {@inheritDoc} */
  public int read() throws IOException
  {
    return read(new byte[1]);
  }


  /** {@inheritDoc} */
  public int read(final byte[] b) throws IOException
  {
    return read(b, 0, b.length);
  }


  /** {@inheritDoc} */
  public int read(final byte[] b, final int off, final int len) throws IOException
  {
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


  private void prepareInputBuffer(final int required)
  {
    if (input == null || input.capacity() < required) {
      input = CharBuffer.allocate(required);
    } else {
      input.clear();
    }
  }

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
