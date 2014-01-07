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

package org.cryptacular.spec;


import org.cryptacular.codec.Base64Codec;
import org.cryptacular.codec.Codec;
import org.cryptacular.codec.HexCodec;

/**
 * Describes a string-to-byte encoding with methods to instantiate the appropriate {@link Encoder}/{@link Decoder}.
 *
 * @author Marvin S. Addison
 */
public class CodecSpec implements Spec<Codec>
{
  /** Hexadecimal encoding specification. */
  public static final CodecSpec HEX = new CodecSpec("Hex");

  /** Base64 encoding specification. */
  public static final CodecSpec BASE64 = new CodecSpec("Base64");


  /** Name of encoding, e.g. "Hex, "Base64". */
  private String encoding;


  /**
   * Creates a new instance of the given encoding.
   *
   * @param  encoding  Name of encoding.
   */
  public CodecSpec(final String encoding)
  {
    if (encoding == null) {
      throw new IllegalArgumentException("Encoding cannot be null.");
    }
    this.encoding = encoding;
  }


  /**
   * @return  The name of the encoding, e.g. "Hex", "Base64".
   */
  public String getAlgorithm()
  {
    return encoding;
  }


  /** {@inheritDoc} */
  public Codec newInstance()
  {
    final Codec codec;
    if ("Hex".equalsIgnoreCase(encoding)) {
      codec = new HexCodec();
    } else if ("Base64".equalsIgnoreCase(encoding) || "Base-64".equalsIgnoreCase(encoding)) {
      codec = new Base64Codec();
    } else {
      throw new IllegalArgumentException("Invalid encoding.");
    }
    return codec;
  }


  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    return encoding;
  }
}
