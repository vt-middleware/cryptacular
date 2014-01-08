---
layout: default
title: Cryptacular
---
The spectacular complement to the Bouncy Castle crypto API for Java.

## Spectacularly familiar
Perform common cryptographic operations using the familiar lightweight Bouncy Castle API.

{% highlight java %}
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

## Spectacularly secure
Cryptography contains a number of pitfalls in the details, and Cryptacular components that do the right thing by
default and APIs that suggest the right component to perform a particular operation according to best practices.

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

## Spectacularly convenient
Cryptacular provides a number of components to facilitate common use cases.

{% highlight java %}
// Static utility classes to quickly perform common operations
byte[] hash = HashUtil.sha1(ByteUtil.toBytes("Some text"));
{% endhighlight %}

{% highlight java %}
// Factory beans for keys and keystores
{% endhighlight %}

{% highlight java %}
// Thread-safe beans for cryptographic operations
final HashBean bean = new SaltedHashBean();
bean.setDigestSpec(new DigestSpec("SHA-256"));
bean.setCodecSpec(CodecSpec.HEX);
bean.setNonce(new RGBNonce());
bean.setIterations(5);
final String hexHash = bean.digest(ByteUtil.toBytes("password"));
{% endhighlight %}
