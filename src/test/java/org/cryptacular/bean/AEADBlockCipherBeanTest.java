/* See LICENSE for licensing and NOTICE for copyright. */
package org.cryptacular.bean;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.security.KeyStore;
import org.cryptacular.FailListener;
import org.cryptacular.generator.sp80038d.CounterNonce;
import org.cryptacular.io.FileResource;
import org.cryptacular.spec.AEADBlockCipherSpec;
import org.cryptacular.util.ByteUtil;
import org.cryptacular.util.CodecUtil;
import org.cryptacular.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link AEADBlockCipherBean}.
 *
 * @author  Middleware Services
 */
@Listeners(FailListener.class)
public class AEADBlockCipherBeanTest
{

  @DataProvider(name = "test-arrays")
  public Object[][] getTestArrays()
  {
    return
      new Object[][] {
        new Object[] {
          // Plaintext is NOT multiple of block size
          "Able was I ere I saw elba.",
          "AES/GCM",
        },
        // Plaintext is multiple of block size
        new Object[] {
          "Four score and seven years ago, our forefathers ",
          "Twofish/CCM",
        },
        // OCB
        new Object[] {
          "Have you passed through this night?",
          "Twofish/OCB",
        },
        // EAX
        new Object[] {
          "I went to the woods because I wished to live deliberately, to front only the essential facts of life",
          "AES/EAX",
        },
      };
  }

  @DataProvider(name = "test-streams")
  public Object[][] getTestStreams()
  {
    return
      new Object[][] {
        new Object[] {
          "src/test/resources/plaintexts/lorem-5000.txt",
          "Twofish/GCM",
        },
        new Object[] {
          "src/test/resources/plaintexts/lorem-1200.txt",
          "AES/OCB",
        },
        new Object[] {
          "src/test/resources/plaintexts/lorem-1200.txt",
          "AES/EAX",
        },
      };
  }


  @Test(dataProvider = "test-arrays")
  public void testEncryptDecryptArray(final String input, final String cipherSpecString)
    throws Exception
  {
    final AEADBlockCipherBean cipherBean = newCipherBean(AEADBlockCipherSpec.parse(cipherSpecString));
    final byte[] ciphertext = cipherBean.encrypt(ByteUtil.toBytes(input));
    assertEquals(ByteUtil.toString(cipherBean.decrypt(ciphertext)), input);
  }


  @Test(dataProvider = "test-streams")
  public void testEncryptDecryptStream(final String path, final String cipherSpecString)
    throws Exception
  {
    final AEADBlockCipherBean cipherBean = newCipherBean(AEADBlockCipherSpec.parse(cipherSpecString));
    final ByteArrayOutputStream tempOut = new ByteArrayOutputStream(8192);
    cipherBean.encrypt(StreamUtil.makeStream(new File(path)), tempOut);

    final ByteArrayInputStream tempIn = new ByteArrayInputStream(tempOut.toByteArray());
    final ByteArrayOutputStream finalOut = new ByteArrayOutputStream(8192);
    cipherBean.decrypt(tempIn, finalOut);
    assertEquals(ByteUtil.toString(finalOut.toByteArray()), ByteUtil.toString(StreamUtil.readAll(path)));
  }


  @Test
  public void testDecryptArrayBackwardCompatibleHeader()
  {
    final AEADBlockCipherBean cipherBean = newCipherBean(new AEADBlockCipherSpec("Twofish", "OCB"));
    final String expected = "Have you passed through this night?";
    final String v1CiphertextHex =
        "0000001f0000000c76746d770002ba17043672d900000007767463727970745a38dee735266e3f5f7aafec8d1c9ed8a0830a2ff9" +
        "c3a46c25f89e69b6eb39dbb82fd13da50e32b2544a73f1a4476677b377e6";
    final byte[] plaintext = cipherBean.decrypt(CodecUtil.hex(v1CiphertextHex));
    assertEquals(expected, ByteUtil.toString(plaintext));
  }


  @Test
  public void testDecryptStreamBackwardCompatibleHeader()
  {
    final AEADBlockCipherBean cipherBean = newCipherBean(new AEADBlockCipherSpec("Twofish", "OCB"));
    final String expected = "Have you passed through this night?";
    final String v1CiphertextHex =
      "0000001f0000000c76746d770002ba17043672d900000007767463727970745a38dee735266e3f5f7aafec8d1c9ed8a0830a2ff9" +
        "c3a46c25f89e69b6eb39dbb82fd13da50e32b2544a73f1a4476677b377e6";
    final ByteArrayInputStream in = new ByteArrayInputStream(CodecUtil.hex(v1CiphertextHex));
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    cipherBean.decrypt(in, out);
    assertEquals(expected, ByteUtil.toString(out.toByteArray()));
  }


  private static KeyStore getTestKeyStore()
  {
    final KeyStoreFactoryBean bean = new KeyStoreFactoryBean();
    bean.setPassword("vtcrypt");
    bean.setResource(new FileResource(new File("src/test/resources/keystores/cipher-bean.jceks")));
    bean.setType("JCEKS");
    return bean.newInstance();
  }


  private static AEADBlockCipherBean newCipherBean(final AEADBlockCipherSpec cipherSpec)
  {
    final AEADBlockCipherBean cipherBean = new AEADBlockCipherBean();
    cipherBean.setNonce(new CounterNonce("vtmw", System.nanoTime()));
    cipherBean.setKeyAlias("vtcrypt");
    cipherBean.setKeyPassword("vtcrypt");
    cipherBean.setKeyStore(getTestKeyStore());
    cipherBean.setBlockCipherSpec(cipherSpec);
    return cipherBean;
  }
}
