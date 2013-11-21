package org.cryptosis;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.bouncycastle.util.io.Streams;

/**
 * Utility methods for stream handling.
 *
 * @author Marvin S. Addison
 */
public final class StreamUtil
{
  /** Private method of utility class. */
  private StreamUtil() {}


  public static byte[] readAll(final String path)
  {
    return readAll(new File(path));
  }


  public static byte[] readAll(final File file)
  {
    return readAll(makeStream(file), (int) file.length());
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


  public static InputStream makeStream(final File file)
  {
    try {
      return new BufferedInputStream(new FileInputStream(file));
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
}
