package org.cryptosis.bean;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.security.KeyStore;
import javax.crypto.SecretKey;

import org.cryptosis.generator.CounterNonce;
import org.cryptosis.generator.EncryptedNonce;
import org.cryptosis.io.FileResource;
import org.cryptosis.spec.AEADBlockCipherSpec;
import org.cryptosis.spec.BufferedBlockCipherSpec;
import org.cryptosis.util.ByteUtil;
import org.cryptosis.util.StreamUtil;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

/**
 * Unit test for {@link AEADBlockCipherBean}.
 *
 * @author Marvin S. Addison
 */
public class AEADBlockCipherBeanTest
{
  @DataProvider(name = "test-arrays")
  public Object[][] getTestArrays()
  {
    return new Object[][] {
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
    return new Object[][] {
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
  public void testEncryptDecryptArray(final String input, final String cipherSpecString) throws Exception
  {
    final AEADBlockCipherBean cipherBean = new AEADBlockCipherBean();
    final AEADBlockCipherSpec cipherSpec = AEADBlockCipherSpec.parse(cipherSpecString);
    cipherBean.setNonce(new CounterNonce("vtmw", System.nanoTime()));
    cipherBean.setKeyAlias("vtcrypt");
    cipherBean.setKeyPassword("vtcrypt");
    cipherBean.setKeyStore(getTestKeyStore());
    cipherBean.setBlockCipherSpec(cipherSpec);
    final byte[] ciphertext = cipherBean.encrypt(ByteUtil.toBytes(input));
    assertEquals(ByteUtil.toString(cipherBean.decrypt(ciphertext)), input);
  }


  @Test(dataProvider = "test-streams")
  public void testEncryptDecryptStream(final String path, final String cipherSpecString) throws Exception
  {
    final AEADBlockCipherBean cipherBean = new AEADBlockCipherBean();
    final AEADBlockCipherSpec cipherSpec = AEADBlockCipherSpec.parse(cipherSpecString);
    cipherBean.setNonce(new CounterNonce("vtmw", System.nanoTime()));
    cipherBean.setKeyAlias("vtcrypt");
    cipherBean.setKeyPassword("vtcrypt");
    cipherBean.setKeyStore(getTestKeyStore());
    cipherBean.setBlockCipherSpec(cipherSpec);
    final ByteArrayOutputStream tempOut = new ByteArrayOutputStream(8192);
    cipherBean.encrypt(StreamUtil.makeStream(new File(path)), tempOut);
    final ByteArrayInputStream tempIn = new ByteArrayInputStream(tempOut.toByteArray());
    final ByteArrayOutputStream finalOut = new ByteArrayOutputStream(8192);
    cipherBean.decrypt(tempIn, finalOut);
    assertEquals(ByteUtil.toString(finalOut.toByteArray()), ByteUtil.toString(StreamUtil.readAll(path)));
  }


  private static KeyStore getTestKeyStore()
  {
    final KeyStoreFactoryBean bean = new KeyStoreFactoryBean();
    bean.setPassword("vtcrypt");
    bean.setResource(new FileResource(new File("src/test/resources/keystores/cipher-bean.jceks")));
    bean.setType("JCEKS");
    return bean.newInstance();
  }

  private static SecretKey getTestKey()
  {
    final KeyStoreBasedSecretKeyFactoryBean secretKeyFactoryBean = new KeyStoreBasedSecretKeyFactoryBean();
    secretKeyFactoryBean.setKeyStore(getTestKeyStore());
    secretKeyFactoryBean.setPassword("vtcrypt");
    secretKeyFactoryBean.setAlias("vtcrypt");
    return secretKeyFactoryBean.newInstance();
  }
}
