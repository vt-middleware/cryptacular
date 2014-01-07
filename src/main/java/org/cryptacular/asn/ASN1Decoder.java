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

package org.cryptacular.asn;

/**
 * Strategy interface for converting encoded ASN.1 bytes to an object.
 *
 * @author Marvin S. Addison
 * @param  <T>  Type of object to produce on decode.
 */
public interface ASN1Decoder<T>
{
  /**
   * Produces an object from an encoded representation.
   *
   * @param  encoded  ASN.1 encoded data.
   * @param  args  Additional data required to perform decoding.
   *
   * @return  Decoded object.
   */
  T decode(byte[] encoded, Object ... args);
}
