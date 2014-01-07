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

import java.io.IOException;
import java.io.OutputStream;

/**
 * Callback interface that supports arbitrary processing of data chunks read from an input stream.
 *
 * @author Marvin S. Addison
 */
public interface ChunkHandler
{
  /**
   * Processes the given chunk of data and writes it to the output stream.
   *
   * @param  input  Chunk of input data to process.
   * @param  offset  Offset into input array where data to process starts.
   * @param  count  Number of bytes of input data to process.
   * @param  output  Output stream where processed data is written.
   *
   * @throws  IOException  On IO errors.
   */
  void handle(byte[] input, int offset, int count, OutputStream output) throws IOException;
}
