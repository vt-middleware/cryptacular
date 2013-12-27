package org.cryptosis.io;

import java.io.IOException;
import java.io.InputStream;

/**
 * Resource descriptor that provides a strategy to get an {@link InputStream} to read bytes.
 *
 * @author Marvin S. Addison
 */
public interface Resource
{
  /**
   * Gets an input stream around the resource. Callers of this method are responsible for resource cleanup; it should
   * be sufficient to simply call {@link java.io.InputStream#close()} unless otherwise noted.
   * <p>
   * Implementers should produce a new instance on every call to this method to provide for thread-safe usage patterns
   * on a shared resource.
   *
   * @return  Input stream around underlying resource, e.g. file, remote resource (URI), etc.
   *
   * @throws  IOException  On IO errors.
   */
  InputStream getInputStream() throws IOException;
}
