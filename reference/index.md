---
layout: default
title: Cryptacular Reference Manual
---

The reference manual discusses the Cryptacular library from the perspective of a developer trying to get work done,
and as such we rely heavily on examples to demonstrate usage. We discuss some design matters where relevant,
but the reference manual is first and foremost a developer usage guide. The best reference on library design is the
source itself.

## Front matter

### About examples

There are some notable conventions used in the following examples:

1. All unqualified class names are either well-known classes in the JSE (e.g. FileInputStream) or Cryptacular components
2. We make copious use of comments to clarify operations and the purpose of method parameters

### Thread safety

One of the most common pitfalls in cryptographic code is inattention to thread safety issues. In many cases problems
arise from poor documentation around whether components and their dependencies are thread safe. Cryptacular provides
a straightforward convention that identifies whether a component is safe.

A Cryptacular component is thread safe if any of the following is true:

1. Name ends with `Util` (e.g.
[`CipherUtil`](/cryptacular/javadocs/org/cryptacular/util/CipherUtil.html),
[`HashUtil`](/cryptacular/javadocs/org/cryptacular/util/HashUtil.html))
2. Name ends with `Bean` (e.g.
[`SimpleHashBean`](/cryptacular/javadocs/org/cryptacular/bean/SimpleHashBean.html),
[`AEADBlockCipherBean`](/cryptacular/javadocs/org/cryptacular/bean/AEADBlockCipherBean.html))
3. Class is in `generator` package (e.g.
[`RandomIdGenerator`](/cryptacular/javadocs/org/cryptacular/generator/RandomIdGenerator.html),
[`RBGNonce`](/cryptacular/javadocs/org/cryptacular/generator/sp80038a/RBGNonce.html))
4. Class is in `spec` package (e.g.
[`DigestSpec`](/cryptacular/javadocs/org/cryptacular/spec/DigestSpec.html),
[`BufferedBlockCipherSpec`](/cryptacular/javadocs/org/cryptacular/spec/BufferedBlockCipherSpec.html))

Otherwise the component should be considered not thread safe unless explicity noted in the JavaDocs.

### Organization

The remainder of the reference is organized by broad categories of either cryptographic operation or component type.
We cover only the most common components, component classes, and usage scenarios, but that ought to be a complete
introduction to library usage. The [JavaDocs](/cryptacular/javadocs/) and [source](
http://github.com/vt-middleware/cryptacular) are intended to complement and complete the reference guide.

## Hashing

Cryptacular provides a number of components for common hashing operations such as hashing with output encoding
(e.g. hex) and salted hash comparison (e.g. password comparison). The following examples demonstrate common operations.

{% highlight java %}
// Compute the SHA-1 hash of a string
byte[] sha1Bytes = HashUtil.sha1("Codito ergo sum");

// Compute the hex-encoded SHA-256 hash of a string
String sha256Hex = CodecUtil.hex(HashUtil.sha256("Ecce homo"));

// Note that HashUtil handles several input types directly:
// - CharSequence (converts to UTF-8 bytes)
// - InputStream (reads stream as bytes)
// - Resource (reads contents as bytes)
// Thus the usage for hashing a stream is the same as a string
byte[] sha256Bytes = HashUtil.sha256(new FileInputStream("/path/to/data"));
{% endhighlight %}

A common password authentication routine follows.

{% highlight java %}
// Compute a salted SHA-1 hash of an input string and compare it to a value of
// record stored as a base64-encoded string stored in "authoritativeHashString".
// The stored value is thus base64(A+B), where A is the salted SHA-1 hash bytes
// and B is the salt bytes. LDAP directories store password hashes this way.

// Create a SaltedHash object to store the value to compare against
SaltedHash authoritativeHash = new SaltedHash(
  CodecUtil.b64(authoritativeHashString), // String to bytes
  20, // SHA-1 hashes are 160 bits/20 bytes long,
  true); // Salt is appended to the end of the hash bytes

// Perform the hash comparison
boolean areEqual = HashUtil.compareHash(
  new org.bouncycastle.crypto.digests.SHA1Digest(),
  authoritativeHash,
  1, // One hashing round,
  "Th3P@ssw0rd"); // Input string to hash and compare
{% endhighlight %}

## Encryption and decryption

Cryptacular provides a novel feature in its encryption routines that addresses a common pitfall in cryptographic coding, failing to provide a unique initialization vector (IV, nonce) on every encryption. Cryptography standards such as
[NIST 800-38d](http://goo.gl/kE1IT9) are clear that unique nonces are required for every encryption under the same key
in order to provide any meaningful security. Cryptacular cipher routines force adherence to this practice by requiring
a [Nonce](/cryptacular/javadocs/org/cryptacular/generator/Nonce.html) object, a kind of generator,
that produces a unique nonce for every encryption. The nonce and an optional symbolic key name are 
prepended to the beginning of the output where they become effectively a cleartext superblock containing information
about the following ciphertext. The superblock is subsequently used in decryption routines; since the nonce is stored
with the ciphertext, it is not needed for decryption. The symbolic key name is intended to support key rollover
processes where a hint is provided through the symbolic name about which of several possible keys was used to encrypt
the ciphertext.

The following example demonstrates a complete encryption and decryption process. [AEAD-mode](
https://en.wikipedia.org/wiki/Authenticated_encryption) ciphers are demonstrated here
and recommended for new software.

{% highlight java %}
// Define the underlying AES cipher used for encryption/decryption
BlockCipher block = new org.bouncycastle.crypto.engines.AESEngine();

// Wrap the underlying AES block cipher in a GCM mode cipher
AEADBlockCipher cipher = new org.bouncycastle.crypto.modes.GCMBlockCipher(block); 

// We generate a new 128-bit AES key here, but one could be loaded from a
// Keystore or other secure storage
SecretKey key = SecretKeyGenerator.generate(128, block);

// Take care to use a suitable Nonce class for the chosen cipher mode
// org.cryptacular.generator.sp80038d.RBGNonce - AEAD-mode ciphers
// org.cryptacular.generator.sp80038a.RBGNonce - block mode (e.g. CBC) ciphers
Nonce nonce = new org.cryptacular.generator.sp80038d.RBGNonce();

//============
// Encryption
//============
// Create input stream around the original plaintext input to encrypt
InputStream inPlain = new FileInputStream("/path/to/plain.txt");

// Create output stream to the file that will hold base64-encoded ciphertext
OutputStream outCipher = new EncodingOutputStream(
  new FileOutputStream("/path/to/cipher.b64"),
  new Base64Encoder(72)); // Line breaks at 72 chars per line

// Perform encryption
CipherUtil.encrypt(aeadCipher, key, nonce, inPlain, outCipher);

//============
// Decryption
//============
// Create input stream around ciphertext input
// Note we have to handle base64 decoding
InputStream inCipher = new DecodingInputStream(
  new FileInputStream("/path/to/cipher.b64"),
  new Base64Decoder());

// Create output stream to hold decrypted plaintext
OutputStream outPlain = new EncodingOutputStream(
  new FileOutputStream("/path/to/plain2.txt"));

// Perform decryption
CipherUtil.decrypt(aeadCipher, key, inCipher, outPlain);
{% endhighlight %}

## Beans

The `beans` package provides thread safe components for common cryptographic operations: hashing, encryption, and key
management. Beans are configuration containers that allow reproducible operations with a particular configuration set;
for example, encryption under a particular key or hashing under a particular number of rounds.

In the following sections we provide examples of notable beans used in common scenarios. We provide [Spring XML](
http://goo.gl/i0ZBnx) configuration along with each Java source excerpt to underscore component wiring, which is a
primary consideration when using beans.

### Encryption beans

The following example demonstrates how to perform encryption and decryption of data under a key that is
handled securely. All ciphertext data is base64 encoded to allow for more convenient handling.

{% highlight xml%}
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:c="http://www.springframework.org/schema/c"
       xmlns:p="http://www.springframework.org/schema/p"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
         http://www.springframework.org/schema/beans
         http://www.springframework.org/schema/beans/spring-beans.xsd">

  <bean id="keyStoreFactory"
        class="org.cryptacular.bean.KeyStoreFactoryBean"
        c:resource="/path/to/keystore"
        c:type="JCEKS"
        c:password="changeit" />

  <bean id="keyStore"
        factory-bean="keystoreFactory"
        factory-method="newInstance" />

  <bean id="cipherBean"
        class="org.cryptacular.bean.AEADBlockCipherBean"
        p:keyStore-ref="keystore"
        p:keyAlias="keyAliasInKeyStore"
        p:keyPassword="changeit">
    <property name="blockCipherSpec">
      <bean class="org.cryptacular.spec.AEADBlockCipherSpec"
            c:algorithm="AES"
            c:mode="GCM" />
    </property>
    <property name="nonce">
      <bean class="org.cryptacular.generator.sp80038d.RBGNonce" />
    </property>
  </bean>
</beans>
{% endhighlight %}

{% highlight java %}
@org.springframework.stereotype.Service
public class EncryptionService() {
  @Inject
  private CipherBean cipherBean;

  private Encoder encoder = new Base64Encoder(72);

  private Decoder decoder = new Base64Decoder();

  public String encrypt(String plainText) {
    return encoder.encode(cipherBean.encrypt(ByteUtil.toBytes(plainText)));
  }

  public String decrypt(String cipherText) {
    return ByteUtil.toString(cipherBean.decrypt(decoder.decode(cipherText)));
  }
}
{% endhighlight %}

### Hash beans

The following example demonstrates how to generate a salted, hex encoded SHA-256 hash digest from a user-supplied
password and salt.

{% highlight xml%}
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:c="http://www.springframework.org/schema/c"
       xmlns:p="http://www.springframework.org/schema/p"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xsi:schemaLocation="
         http://www.springframework.org/schema/beans
         http://www.springframework.org/schema/beans/spring-beans.xsd">

  <bean id="hashBean"
        class="org.cryptacular.bean.EncodingHashBean"
        p:iterations="10"
        p:salted="true">
    <property name="codecSpec">
      <bean class="org.cryptacular.spec.CodecSpec" c:encoding="Hex" />
    </property>
    <property name="digestSpec">
      <bean class="org.cryptacular.spec.DigestSpec" c:algName="SHA256" />
    </property>
  </bean>
</beans>
{% endhighlight %}

{% highlight java %}
@org.springframework.stereotype.Service
public class PasswordHashService() {
  @Inject
  private HashBean<String> hashBean;

  public String hash(String password, String byte[] salt) {
    // Hash beans handle conversion of objects to bytes for common input types
    // See HashUtil#hash() JavaDocs for more information
    return hashBean.hash(password, salt);
  }
{% endhighlight %}
