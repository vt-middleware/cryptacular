/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.io;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import org.cryptacular.CryptUtil;

/**
 * Describes a (presumably remote) resource accessible via URL.
 *
 * @author  Middleware Services
 */
public class URLResource implements Resource
{

  /** Location of resource. */
  private final URL url;


  /**
   * Creates a new URL resource.
   *
   * @param  url  Non-null URL where resource is located.
   */
  public URLResource(final URL url)
  {
    this.url = CryptUtil.assertNotNullArg(url, "URL cannot be null.");
  }


  @Override
  public InputStream getInputStream()
    throws IOException
  {
    return url.openStream();
  }


  @Override
  public String toString()
  {
    return url.toString();
  }
}
