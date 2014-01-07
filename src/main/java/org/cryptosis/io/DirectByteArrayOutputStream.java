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

package org.cryptosis.io;

import java.io.ByteArrayOutputStream;

/**
 * Extends {@link ByteArrayOutputStream} by allowing direct access to the internal byte buffer.
 *
 * @author  Marvin S. Addison
 */
public class DirectByteArrayOutputStream extends ByteArrayOutputStream
{

  /** Creates a new instance with a buffer of the default size. */
  public DirectByteArrayOutputStream()
  {
    super();
  }


  /**
   * Creates a new instance with a buffer of the given initial capacity.
   *
   * @param  capacity  Initial capacity of internal buffer.
   */
  public DirectByteArrayOutputStream(final int capacity)
  {
    super(capacity);
  }


  /**
   * Gets the internal byte buffer.
   *
   * @return  Internal buffer that holds written bytes.
   */
  public byte[] getBuffer()
  {
    return buf;
  }
}
