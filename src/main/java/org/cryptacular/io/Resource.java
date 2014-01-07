/*
 * Licensed to Virginia Tech under one or more contributor license
 * agreements. See the NOTICE file distributed with this work
 * for additional information regarding copyright ownership.
 * Virginia Tech licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain a
 * copy of the License at the following location:
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.cryptacular.io;

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
