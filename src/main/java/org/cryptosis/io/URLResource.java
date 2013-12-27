package org.cryptosis.io;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;

/**
 * Describes a (presumably remote) resource accessible via URL.
 *
 * @author Marvin S. Addison
 */
public class URLResource implements Resource
{
  /** Location of resource. */
  private URL url;


  /**
   * Creates a new URL resource.
   *
   * @param  url Non-null URL where resource is located.
   */
  public URLResource(final URL url)
  {
    if (url == null) {
      throw new IllegalArgumentException("URL cannot be null.");
    }
    this.url = url;
  }


  /** {@inheritDoc} */
  @Override
  public InputStream getInputStream() throws IOException
  {
    return url.openStream();
  }
}
