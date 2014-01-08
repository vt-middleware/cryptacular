---
layout: default
title: Cryptacular
---
The spectacular complement to the Bouncy Castle crypto API for Java.

## Spectacularly familiar
Perform common cryptographic operations using familiar APIS, JCE and lightweight Bouncy Castle API.

{% highlight java %}
final AEADBlockCipher cipher = new GCMBlockCipher(new AESEngine());
final SecretKey key = SecretKeyGenerator.generate(cipher.getUnderlyingCipher());
final File file = new File("/path/to/plain.txt");
final String expected = new String(StreamUtil.readAll(file));
final ByteArrayOutputStream tempOut = new ByteArrayOutputStream();
CipherUtil.encrypt(cipher, key, new RBGNonce(), StreamUtil.makeStream(file), tempOut);
{% endhighlight %}

## Spectacularly secure
Cryptography contains a number of pitfalls in the details, and Cryptacular provides prophylaxis:

* Components that do the right thing by default
* APIs that suggest the right component to perform a particular operation according to best practices

{% highlight java %}
// Cryptacular forces the use of a dynamic IV per encryption,
// one of the most common pitfalls for block ciphers,
// and makes storage of the IV secure and convenient for decryption
final BufferedBlockCipherBean cipherBean = new BufferedBlockCipherBean();
final BufferedBlockCipherSpec cipherSpec = BufferedBlockCipherSpec.parse(cipherSpecString);
cipherBean.setNonce(nonce);
cipherBean.setKeyAlias("vtcrypt");
cipherBean.setKeyPassword("vtcrypt");
cipherBean.setKeyStore(getTestKeyStore());
cipherBean.setBlockCipherSpec(cipherSpec);
final byte[] ciphertext = cipherBean.encrypt(ByteUtil.toBytes(input));
assertEquals(ByteUtil.toString(cipherBean.decrypt(ciphertext)), input);
{% endhighlight %}

Beyond avoiding cryptography errors, Cryptacular ships with components that encourage use of modern algorithms
(e.g. GCM ciphers, SHA-3 digest) and current standard (e.g. NIST SP-800-63).

## Spectacularly convenient
Cryptacular provides a number of components to facilitate common use cases.

{% highlight java %}
// Static utility classes to quickly perform common operations
byte[] hash = HashUtil.sha1(ByteUtil.toBytes("Some text"));
{% endhighlight %}

{% highlight java %}
// Factory beans for keys and keystores
final KeyStoreFactoryBean keyStoreFactory = new KeyStoreFactoryBean();
keyStoreFactory.setResource(new FileResource(new File(keyStorePath)));
keyStoreFactory.setPassword("vtcrypt");
keyStoreFactory.setType(keyStoreType);
final KeyStoreBasedSecretKeyFactoryBean secretKeyFactory = new KeyStoreBasedSecretKeyFactoryBean();
secretKeyFactory.setKeyStore(keyStoreFactory.newInstance());
secretKeyFactory.setAlias(alias);
secretKeyFactory.setPassword("vtcrypt");
final SecretKey key = secretKeyFactory.newInstance();
{% endhighlight %}

{% highlight java %}
// Thread-safe beans for cryptographic operations
final HashBean bean = new SaltedHashBean();
bean.setDigestSpec(new DigestSpec("SHA-256"));
bean.setCodecSpec(CodecSpec.HEX);
bean.setSaltSource(new RBGNonce());
bean.setIterations(5);
final String hexHash = bean.digest(ByteUtil.toBytes("password"));
{% endhighlight %}
