/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.io;

import java.io.InputStream;

/**
 * Resource that produces a {@link InputStream} from a classpath resource.
 *
 * @author  Middleware Services
 */
public class ClassPathResource implements Resource
{

  /** Classpath location of resource. */
  private final String classPath;

  /** Class loader used to get input streams on classpath locations. */
  private final ClassLoader classLoader;


  /**
   * Creates a new resource that reads from the given classpath location. <code>
   * Thread.currentThread().getContextClassLoader()</code> is used to obtain the
   * class loader used to obtain an input stream on the given classpath.
   *
   * @param  path  Classpath location.
   */
  public ClassPathResource(final String path)
  {
    this(path, Thread.currentThread().getContextClassLoader());
  }


  /**
   * Creates a new resource that reads from the given classpath location.
   *
   * @param  path  Classpath location.
   * @param  loader  Class loader used to obtain an input stream on the given
   *                 classpath location.
   */
  public ClassPathResource(final String path, final ClassLoader loader)
  {
    // Strip leading / since absolute paths are not supported by
    // ClassLoader#getResourceAsStream(...)
    if (path.startsWith("/")) {
      this.classPath = path.substring(1);
    } else {
      this.classPath = path;
    }
    this.classLoader = loader;
  }


  /** {@inheritDoc} */
  @Override
  public InputStream getInputStream()
  {
    return classLoader.getResourceAsStream(classPath);
  }
}
