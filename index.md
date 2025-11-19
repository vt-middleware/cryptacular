---
layout: default
title: Cryptacular
---
Cryptacular is a complement to the [Bouncy Castle Crypto APIs for Java](https://www.bouncycastle.org/java.html)
that is...

## Familiar
Perform common cryptographic operations using familiar APIS, JCE and lightweight Bouncy Castle API.

{% highlight java %}
AEADBlockCipher cipher = GCMBlockCipher.newInstance(AESEngine.newInstance());
SecretKey key = SecretKeyGenerator.generate(cipher.getUnderlyingCipher());
File file = new File("/path/to/plain.txt");
ByteArrayOutputStream tempOut = new ByteArrayOutputStream();
CipherUtil.encrypt(cipher, key, new RBGNonce(), StreamUtil.makeStream(file), tempOut);
{% endhighlight %}

## Secure
Cryptography contains a number of pitfalls in the details, and Cryptacular provides prophylaxis:

* Components that do the right thing by default
* APIs that suggest the right component to perform a particular operation according to best practices

{% highlight java %}
// Cryptacular forces the use of a dynamic IV per encryption,
// one of the most common pitfalls for block ciphers,
// and makes storage of the IV secure and convenient for decryption
BufferedBlockCipherBean cipherBean = new BufferedBlockCipherBean(
  BufferedBlockCipherSpec.parse(cipherSpecString),
  getTestKeyStore(),
  "alias",
  "p@ssw0rd",
  nonce);
byte[] ciphertext = cipherBean.encrypt(ByteUtil.toBytes(input));
assertEquals(ByteUtil.toString(cipherBean.decrypt(ciphertext)), input);
{% endhighlight %}

Beyond avoiding cryptography errors, Cryptacular ships with components that encourage use of modern algorithms
(e.g. GCM ciphers, SHA-3 digest) and current standard (e.g. NIST SP-800-63).

## Convenient
Cryptacular facilitates common use cases and provides extension points to for complex cases.

{% highlight java %}
// Static utility classes to quickly perform common operations
byte[] hash = HashUtil.sha1("Some text");
{% endhighlight %}

{% highlight java %}
// Consistent API for handling stream data as easily as strings/bytes
byte[] hash = HashUtil.sha1(StreamUtil.makeStream(file));
{% endhighlight %}

{% highlight java %}
// Factory beans for keys and keystores
KeyStoreFactoryBean keyStoreFactory = new KeyStoreFactoryBean(
  new FileResource(new File(keyStorePath)),
  keyStoreType,
  "p@ssw0rd");
KeyStoreBasedKeyFactoryBean<SecretKey> secretKeyFactory = new KeyStoreBasedKeyFactoryBean<>(
  keyStoreFactory.newInstance(),
  "alias",
  "p@ssw0rd");
SecretKey key = secretKeyFactory.newInstance();
{% endhighlight %}

{% highlight java %}
// Thread-safe beans for cryptographic operations
// Here we demonstrate a bean to compute password hashes in a secure manner
EncodingHashBean bean = new EncodingHashBean(
  CodecSpec.HEX,
  new DigestSpec("SHA-256"),
  5);
Nonce saltSource = new RBGNonce(8);
String hexHash = bean.hash("password", saltSource.generate());
{% endhighlight %}

