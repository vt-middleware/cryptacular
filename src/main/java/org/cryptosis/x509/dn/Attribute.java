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

package org.cryptosis.x509.dn;

/**
 * Simple implementation of the X.501 AttributeTypeAndValue that makes up the RelativeDistinguishedName type described
 * in section 4.1.2.4 of RFC 2459.
 *
 * @author Marvin S. Addison
 */
public class Attribute
{
  /** Attribute type. */
  private final AttributeType type;

  /** Attribute value. */
  private final String value;


  /**
   * Creates a new instance of the given type and value.
   *
   * @param  type  Attribute type.
   * @param  value  Attribute value.
   */
  public Attribute(final AttributeType type, final String value)
  {
    if (type == null) {
      throw new IllegalArgumentException("Type cannot be null.");
    }
    this.type = type;
    if (value == null) {
      throw new IllegalArgumentException("Value cannot be null.");
    }
    this.value = value;
  }


  /**
   * @return  Attribute type.
   */
  public AttributeType getType()
  {
    return type;
  }


  /**
   * @return  Attribute value.
   */
  public String getValue()
  {
    return value;
  }


  /** {@inheritDoc} */
  @Override
  public String toString()
  {
    return value;
  }
}
