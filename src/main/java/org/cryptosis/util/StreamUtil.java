package org.cryptosis.util;

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
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;

import org.bouncycastle.util.io.Streams;
import org.cryptosis.io.ChunkHandler;

/**
 * Utility methods for stream handling.
 *
 * @author Marvin S. Addison
 */
public final class StreamUtil
{
  /** Buffer size of chunked operations, e.g.
   * {@link #pipeAll(java.io.InputStream, java.io.OutputStream, org.cryptosis.io.ChunkHandler)}.
   */
  public static final int CHUNK_SIZE = 1024;

  /** Private method of utility class. */
  private StreamUtil() {}


  public static byte[] readAll(final String path)
  {
    return readAll(new File(path));
  }


  public static byte[] readAll(final File file)
  {
    final InputStream input = makeStream(file);
    try {
      return readAll(input, (int) file.length());
    } finally {
      closeStream(input);
    }
  }


  public static byte[] readAll(final InputStream input)
  {
    return readAll(input, 1024);
  }


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


  public static String readAll(final Reader reader)
  {
    return readAll(reader, 1024);
  }


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


  public static void pipeAll(final InputStream in, final OutputStream out, final ChunkHandler handler)
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


  public static InputStream makeStream(final File file)
  {
    try {
      return new BufferedInputStream(new FileInputStream(file));
    } catch (FileNotFoundException e) {
      throw new RuntimeException(file + " does not exist");
    }
  }


  public static Reader makeReader(final File file)
  {
    try {
      return new InputStreamReader(new BufferedInputStream(new FileInputStream(file)));
    } catch (FileNotFoundException e) {
      throw new RuntimeException(file + " does not exist");
    }
  }


  public static void closeStream(final InputStream in)
  {
    try {
      in.close();
    } catch (IOException e) {
      // Ignore IO errors on close
    }
  }


  public static void closeStream(final OutputStream out)
  {
    try {
      out.close();
    } catch (IOException e) {
      // Ignore IO errors on close
    }
  }


  public static void closeReader(final Reader reader)
  {
    try {
      reader.close();
    } catch (IOException e) {
      // Ignore IO errors on close
    }
  }


  public static void closeWriter(final Writer writer)
  {
    try {
      writer.close();
    } catch (IOException e) {
      // Ignore IO errors on close
    }
  }
}
