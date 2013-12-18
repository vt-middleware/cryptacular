package org.cryptosis.io;

import org.cryptosis.codec.Base64Encoder;
import org.cryptosis.codec.Encoder;
import org.cryptosis.codec.HexEncoder;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * Filters written bytes through an {@link Encoder} such that encoded data is written to the underlying output stream.
 *
 * @author Marvin S. Addison
 */
public class EncodingOutputStream extends FilterOutputStream
{
  /** Performs decoding. */
  private final Encoder encoder;

  /** Wraps the output stream to convert characters to bytes. */
  private final OutputStreamWriter writer;

  /** Receives encoding result. */
  private CharBuffer output;


  /**
   * Creates a new instance that wraps the given stream and performs encoding using the given encoder component.
   *
   * @param  out  Output stream to wrap.
   * @param  e  Encoder that provides on-the-fly encoding.
   */
  public EncodingOutputStream(final OutputStream out, final Encoder e)
  {
    super(out);
    if (e == null) {
      throw new IllegalArgumentException("Encoder cannot be null.");
    }
    this.encoder = e;
    this.writer = new OutputStreamWriter(out);
  }


  /** {@inheritDoc} */
  @Override
  public void write(final int b) throws IOException
  {
    write(new byte[] { (byte) b });
  }


  /** {@inheritDoc} */
  @Override
  public void write(final byte[] b) throws IOException
  {
    write(b, 0, b.length);
  }


  /** {@inheritDoc} */
  @Override
  public void write(final byte[] b, final int off, final int len) throws IOException
  {
    final ByteBuffer input = ByteBuffer.wrap(b, off, len);
    final int required = encoder.outputSize(len - off);
    if (output == null || output.capacity() < required) {
      output = CharBuffer.allocate(required);
    } else {
      output.clear();
    }
    encoder.encode(input, output);
    output.flip();
    writer.write(output.toString());
    writer.flush();
  }


  /** {@inheritDoc} */
  @Override
  public void flush() throws IOException
  {
    writer.flush();
  }


  /** {@inheritDoc} */
  @Override
  public void close() throws IOException
  {
    if (output == null) {
      output = CharBuffer.allocate(8);
    } else {
      output.clear();
    }
    encoder.finalize(output);
    output.flip();
    writer.write(output.toString());
    writer.flush();
    writer.close();
  }


  /**
   * Creates a new instance that produces base64 output in the given stream.
   * <p>
   * <strong>NOTE:</strong> there are no line breaks in the output with this version.
   *
   * @param  out  Wrapped output stream.
   *
   * @return  Encoding output stream that produces base64 output.
   */
  public static EncodingOutputStream base64(final OutputStream out)
  {
    return base64(out, -1);
  }


  /**
   * Creates a new instance that produces base64 output in the given stream.
   * <p>
   * <strong>NOTE:</strong> this version supports output with configurable line breaks.
   *
   * @param  out  Wrapped output stream.
   * @param  lineLength  Length of each base64-encoded line in output. A zero or negative value disables line breaks.
   *
   * @return  Encoding output stream that produces base64 output.
   */
  public static EncodingOutputStream base64(final OutputStream out, final int lineLength)
  {
    return new EncodingOutputStream(out, new Base64Encoder(lineLength));
  }


  /**
   * Creates a new instance that produces hexadecimal output in the given stream.
   * <p>
   * <strong>NOTE:</strong> there are no line breaks in the output.
   *
   * @param  out  Wrapped output stream.
   *
   * @return  Encoding output stream that produces hexadecimal output.
   */
  public static EncodingOutputStream hex(final OutputStream out)
  {
    return new EncodingOutputStream(out, new HexEncoder());
  }

}
