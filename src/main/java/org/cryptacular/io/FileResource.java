/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.io;


import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.cryptacular.CryptUtil;

/**
 * Resource that produces a buffered {@link FileInputStream} from a file.
 *
 * @author  Middleware Services
 */
public class FileResource implements Resource
{

  /** Underlying file resource. */
  private final File file;


  /**
   * Creates a new file resource.
   *
   * @param  file  Non-null file.
   */
  public FileResource(final File file)
  {
    this.file = CryptUtil.assertNotNullArg(file, "File cannot be null.");
  }


  @Override
  public InputStream getInputStream()
    throws IOException
  {
    return new BufferedInputStream(new FileInputStream(file));
  }


  @Override
  public String toString()
  {
    return file.toString();
  }
}
