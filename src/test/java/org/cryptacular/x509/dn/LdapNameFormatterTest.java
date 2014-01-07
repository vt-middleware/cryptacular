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

package org.cryptacular.x509.dn;

import javax.security.auth.x500.X500Principal;

import org.cryptacular.util.CertUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link LdapNameFormatter} class.
 *
 * @author Marvin S. Addison
 */
public class LdapNameFormatterTest
{
  private static final String CRT_PATH = "src/test/resources/certs/";

  @DataProvider(name = "distinguished-names")
  public Object[][] getDistinguishedNames()
  {
    return new Object[][] {
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt").getSubjectX500Principal(),
        "C=US,DC=vt,DC=edu,O=Virginia Polytechnic Institute and State University,CN=Marvin S Addison,UID=1145718",
      },
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "serac-dev-test.crt").getIssuerX500Principal(),
        "SERIALNUMBER=12,CN=DEV Virginia Tech Class 1 Server CA," +
          "O=Virginia Polytechnic Institute and State University,C=US,DC=vt,DC=edu",
      },
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "glider.cc.vt.edu.crt").getSubjectX500Principal(),
        "C=US,DC=edu,DC=vt,ST=Virginia,L=Blacksburg," +
          "O=Virginia Polytechnic Institute and State University," +
          "OU=Middleware-Client,OU=SETI,SERIALNUMBER=1248110657961," +
          "CN=glider.cc.vt.edu",
      },
      new Object[] {
        CertUtil.readCertificate(CRT_PATH + "glider.cc.vt.edu.crt").getIssuerX500Principal(),
        "CN=Virginia Tech Middleware CA,O=Virginia Polytechnic Institute and State University,C=US,DC=vt,DC=edu",
      },
    };
  }


  @Test(dataProvider = "distinguished-names")
  public void testFormat(final X500Principal dn, final String expected) throws Exception
  {
    assertEquals(new LdapNameFormatter().format(dn), expected);
  }
}
