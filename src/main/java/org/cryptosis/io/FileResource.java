package org.cryptosis.io;


import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Resource that produces a buffered {@link FileInputStream} from a file.
 *
 * @author Marvin S. Addison
 */
public class FileResource implements Resource
{
  /** Underlying file resource. */
  private File file;


  /**
   * Creates a new file resource.
   *
   * @param  file  Non-null file.
   */
  public FileResource(final File file)
  {
    if (file == null) {
      throw new IllegalArgumentException("File cannot be null.");
    }
    this.file = file;
  }


  /** {@inheritDoc} */
  @Override
  public InputStream getInputStream() throws IOException
  {
    return new BufferedInputStream(new FileInputStream(file));
  }
}
