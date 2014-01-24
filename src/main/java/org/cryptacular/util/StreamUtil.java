/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.util;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.CharArrayWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import org.bouncycastle.util.io.Streams;
import org.cryptacular.io.ChunkHandler;

/**
 * Utility methods for stream handling.
 *
 * @author  Middleware Services
 */
public final class StreamUtil
{

  /**
   * Buffer size of chunked operations, e.g. {@link
   * #pipeAll(java.io.InputStream, java.io.OutputStream,
   * org.cryptacular.io.ChunkHandler)}.
   */
  public static final int CHUNK_SIZE = 1024;

  /** Private method of utility class. */
  private StreamUtil() {}


  /**
   * Reads all the data from the file at the given path.
   *
   * @param  path  Path to file.
   *
   * @return  Byte array of data read from file.
   */
  public static byte[] readAll(final String path)
  {
    return readAll(new File(path));
  }


  /**
   * Reads all the data from the given file.
   *
   * @param  file  File to read.
   *
   * @return  Byte array of data read from file.
   */
  public static byte[] readAll(final File file)
  {
    final InputStream input = makeStream(file);
    try {
      return readAll(input, (int) file.length());
    } finally {
      closeStream(input);
    }
  }


  /**
   * Reads all the data from the given input stream.
   *
   * @param  input  Input stream to read.
   *
   * @return  Byte array of data read from stream.
   */
  public static byte[] readAll(final InputStream input)
  {
    return readAll(input, 1024);
  }


  /**
   * Reads all the data from the given input stream.
   *
   * @param  input  Input stream to read.
   * @param  sizeHint  Estimate of amount of data to be read in bytes.
   *
   * @return  Byte array of data read from stream.
   */
  public static byte[] readAll(final InputStream input, final int sizeHint)
  {
    final ByteArrayOutputStream output = new ByteArrayOutputStream(sizeHint);
    try {
      Streams.pipeAll(input, output);
    } catch (IOException e) {
      throw new RuntimeException("IO error reading/writing stream", e);
    } finally {
      closeStream(input);
      closeStream(output);
    }
    return output.toByteArray();
  }


  /**
   * Reads all data from the given reader.
   *
   * @param  reader  Reader over character data.
   *
   * @return  Data read from reader.
   */
  public static String readAll(final Reader reader)
  {
    return readAll(reader, 1024);
  }


  /**
   * Reads all data from the given reader.
   *
   * @param  reader  Reader over character data.
   * @param  sizeHint  Estimate of amount of data to be read in number of
   * characters.
   *
   * @return  Data read from reader.
   */
  public static String readAll(final Reader reader, final int sizeHint)
  {
    final CharArrayWriter writer = new CharArrayWriter(sizeHint);
    final char[] buffer = new char[CHUNK_SIZE];
    int len;
    try {
      while ((len = reader.read(buffer)) > 0) {
        writer.write(buffer, 0, len);
      }
    } catch (IOException e) {
      throw new RuntimeException("IO error reading/writing stream", e);
    } finally {
      closeReader(reader);
      closeWriter(writer);
    }
    return writer.toString();
  }


  /**
   * Pipes an input stream into an output stream with chuncked processing.
   *
   * @param  in  Input stream providing data to process.
   * @param  out  Output stream holding processed data.
   * @param  handler  Arbitrary handler for processing input stream.
   */
  public static void pipeAll(
    final InputStream in,
    final OutputStream out,
    final ChunkHandler handler)
  {
    final byte[] buffer = new byte[CHUNK_SIZE];
    int count;
    try {
      while ((count = in.read(buffer)) > 0) {
        handler.handle(buffer, 0, count, out);
      }
    } catch (IOException e) {
      throw new RuntimeException("IO error reading/writing stream", e);
    }
  }


  /**
   * Creates an input stream around the given file.
   *
   * @param  file  Input stream source.
   *
   * @return  Input stream around file.
   */
  public static InputStream makeStream(final File file)
  {
    try {
      return new BufferedInputStream(new FileInputStream(file));
    } catch (FileNotFoundException e) {
      throw new RuntimeException(file + " does not exist");
    }
  }


  /**
   * Creates a reader around the given file that presumably contains character
   * data.
   *
   * @param  file  Reader source.
   *
   * @return  Reader around file.
   */
  public static Reader makeReader(final File file)
  {
    try {
      return
        new InputStreamReader(
          new BufferedInputStream(new FileInputStream(file)));
    } catch (FileNotFoundException e) {
      throw new RuntimeException(file + " does not exist");
    }
  }


  /**
   * Closes the given stream and swallows exceptions that may arise during the
   * process.
   *
   * @param  in  Input stream to close.
   */
  public static void closeStream(final InputStream in)
  {
    try {
      in.close();
    } catch (IOException e) {
      System.err.println("Error closing " + in + ": " + e);
    }
  }


  /**
   * Closes the given stream and swallows exceptions that may arise during the
   * process.
   *
   * @param  out  Output stream to close.
   */
  public static void closeStream(final OutputStream out)
  {
    try {
      out.close();
    } catch (IOException e) {
      System.err.println("Error closing " + out + ": " + e);
    }
  }


  /**
   * Closes the given reader and swallows exceptions that may arise during the
   * process.
   *
   * @param  reader  Reader to close.
   */
  public static void closeReader(final Reader reader)
  {
    try {
      reader.close();
    } catch (IOException e) {
      System.err.println("Error closing " + reader + ": " + e);
    }
  }


  /**
   * Closes the given writer and swallows exceptions that may arise during the
   * process.
   *
   * @param  writer  Writer to close.
   */
  public static void closeWriter(final Writer writer)
  {
    try {
      writer.close();
    } catch (IOException e) {
      System.err.println("Error closing " + writer + ": " + e);
    }
  }
}
