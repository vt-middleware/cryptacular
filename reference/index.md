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

1. All unqualified class names are either well-known classes in the JSE or Cryptacular components.
2. We make copious use of comments to clarify operations and the purpose of method parameters.

### Thread safety

One of the most common pitfalls in cryptographic code is inattention to thread safety issues. In many cases problems
arise from poor documentation around whether components and their dependencies are thread safe. Cryptacular provides
a straightforward convention that identifies whether a component is safe.

A Cryptacular component is thread safe if any of the following is true:

1. Name ends with `Util` (e.g.
[`CipherUtil`](/javadocs/org/cryptacular/util/CipherUtil.html),
[`HashUtil`](/javadocs/org/cryptacular/util/HashUtil.html))
2. Name ends with `Bean` (e.g.
[`SimpleHashBean`](/javadocs/org/cryptacular/bean/SimpleHashBean.html),
[`AEADBlockCipherBean`](/javadocs/org/cryptacular/bean/AEADBlockCipherBean.html))
3. Class is in `generator` package (e.g.
[`RandomIdGenerator`](/javadocs/org/cryptacular/generator/RandomIdGenerator.html),
[`RBGNonce`](/javadocs/org/cryptacular/generator/sp80038a/RBGNonce.html))
4. Class is in `spec` package (e.g.
[`DigestSpec`](/javadocs/org/cryptacular/spec/DigestSpec.html),
[`BufferedBlockCipherSpec`](/javadocs/org/cryptacular/spec/BufferedBlockCipherSpec.html))

Otherwise the component should be considered not thread safe unless explicity noted in the JavaDocs.

### Organization

The remainder of the reference is organized by broad categories of either cryptographic operation or component type.
We cover only the most common components, component classes, and usage scenarios, but that ought to be a complete
introduction to library usage. The [JavaDocs](/javadocs/) and [source](
http://github.com/vt-middleware/cryptacular) are intended to complement and complete the reference guide.

## Hashing

Cryptacular provides a number of components for common hashing operations such as hashing with output encoding
(e.g. hex) and salted hash comparison (e.g. password comparison). The following examples demonstrate common operations.

{% highlight java %}
{% include source/reference/1.java %}
{% endhighlight %}

A common password authentication routine follows.

{% highlight java %}
{% include source/reference/2.java %}
{% endhighlight %}

## Encryption and decryption

Cryptacular provides a novel feature in its encryption routines that addresses a common pitfall in cryptographic coding, failing to provide a unique initialization vector (IV, nonce) on every encryption. Cryptography standards such as
[NIST 800-38d](http://goo.gl/kE1IT9) are clear that unique nonces are required for every encryption under the same key
in order to provide any meaningful security. Cryptacular cipher routines force adherence to this practice by requiring
a [Nonce](/javadocs/org/cryptacular/generator/Nonce.html) object, a kind of generator,
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
{% include source/reference/3.java %}
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

  <bean id="blockCipherSpec"
        class="org.cryptacular.spec.AEADBlockCipherSpec"
        c:algorithm="AES"
        c:mode="GCM" />

  <bean id="nonce"
        class="org.cryptacular.generator.sp80038d.RBGNonce" />

  <bean id="keyStore"
        factory-bean="keystoreFactory"
        factory-method="newInstance" />

  <bean id="cipherBean"
        class="org.cryptacular.bean.AEADBlockCipherBean"
        c:blockCipherSpec-ref="blockCipherSpec"
        c:keyStore-ref="keystore"
        c:keyAlias="keyAliasInKeyStore"
        c:keyPassword="changeit"
        c:nonce-ref="nonce" />
</beans>
{% endhighlight %}

{% highlight java %}
{% include source/reference/4.java %}
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

  <bean id="codecSpec"
        class="org.cryptacular.spec.CodecSpec"
        c:encoding="Hex" />

  <bean id="digestSpec"
        class="org.cryptacular.spec.DigestSpec"
        c:algName="SHA256" />

  <bean id="hashBean"
        class="org.cryptacular.bean.EncodingHashBean"
        c:codecSpec-ref="codecSpec"
        c:digestSpec-ref="disgestSpec"
        c:iterations="10"
        c:salted="true" />
</beans>
{% endhighlight %}

{% highlight java %}
{% include source/reference/5.java %}
{% endhighlight %}
