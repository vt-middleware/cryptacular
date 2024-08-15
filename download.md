---
layout: default
title: Download Cryptacular
---
Download the latest version which includes source code, classes, javadocs, and tests in zip or tar.gz format.

* [cryptacular-{{ site.version }}-dist.tar.gz](/downloads/{{ site.version }}/cryptacular-{{ site.version }}-dist.tar.gz)   [[PGP](downloads/{{ site.version }}/cryptacular-{{ site.version }}-dist.tar.gz.asc)]
* [cryptacular-{{ site.version }}-dist.zip](/downloads/{{ site.version }}/cryptacular-{{ site.version }}-dist.zip)   [[PGP](downloads/{{ site.version }}/cryptacular-{{ site.version }}-dist.tar.gz.asc)]

Individual artifacts are available in the [Maven Central Repository](http://repo1.maven.org/maven2/org/cryptacular/cryptacular/).
If you would like to use this project in your maven build, include the following in your pom.xml:
{% highlight xml %}
<dependencies>
  <dependency>
    <groupId>org.cryptacular</groupId>
    <artifactId>cryptacular</artifactId>
    <version>{{ site.version }}</version>
  </dependency>
</dependencies>
{% endhighlight %}

## Release Notes

### Version 1.2.7 - 15Aug2024 (Requires Java 8)

Issue | Description
:---- | :----------
[cryptacular-71]({{ site.issueURL }}71) | Provide facilities for generating PKCS12 files
[cryptacular-67]({{ site.issueURL }}67) | Add certificate utility methods
[cryptacular-65]({{ site.issueURL }}65) | Add utilities for common CSR operations

### Version 1.2.6 - 14Aug2023 (Requires Java 8)
This version updates bouncycastle to version 1.76.

### Version 1.2.5 - 14Apr2022 (Requires Java 8)
This version changes the bouncycastle artifactId from bcprov-jdk15on to bcprov-jdk18on. See the [BC release notes](https://www.bouncycastle.org/latest_releases.html) for details on this change.

Issue | Description
:---- | :----------
[cryptacular-59]({{ site.issueURL }}59) | TOTP generator bug for non SHA1 digests

### Version 1.2.4 - 06Feb2020 (Requires Java 8)

Issue | Description
:---- | :----------
[cryptacular-52]({{ site.issueURL }}52) | Potential denial of service (CVE-2020-7226)

### Version 1.2.3 - 09Jan2019 (Requires Java 8)

Issue | Description
:---- | :----------
[cryptacular-47]({{ site.issueURL }}47) | Support upper case hex
[cryptacular-44]({{ site.issueURL }}44) | BCrypt implementation inconsistent with null terminator


### Version 1.2.2 - 08May2018 (Requires Java 8)

Issue | Description
:---- | :----------
[cryptacular-40]({{ site.issueURL }}40) | RandomIdGenerator has weak PRNG seeding
[cryptacular-39]({{ site.issueURL }}39) | BCrypt HashBean implementation
[cryptacular-37]({{ site.issueURL }}37) | Incorrect parsing of OpenSSL EC keys

### Version 1.2.1 - 10Jul2017 (Requires Java 8)

Issue | Description
:---- | :----------
[cryptacular-36]({{ site.issueURL }}36) | Upgrade Bouncy Castle to version 1.57

### Version 1.2.0 - 10Aug2016 (Requires Java 8)

Issue | Description
:---- | :----------
[cryptacular-26]({{ site.issueURL }}26) | Upgrade Bouncy Castle to version 1.54
[cryptacular-23]({{ site.issueURL }}23) | EncodingHashBean convenience constructor

### Version 1.1.4 - 27Feb2020 (Requires Java 7)

Issue | Description
:---- | :----------
[cryptacular-56]({{ site.issueURL }}56) | Potential denial of service (CVE-2020-7226)

### Version 1.1.3 - 08May2018 (Requires Java 7)
Same as version 1.2.2 but without Java 8 language features

### Version 1.1.2 - 10Jul2017 (Requires Java 7)

Issue | Description
:---- | :----------
[cryptacular-36]({{ site.issueURL }}36) | Upgrade Bouncy Castle to version 1.57

### Version 1.1.1 - 10Aug2016 (Requires Java 7)
Same as version 1.2.0 but without Java 8 language features

### Version 1.1.0 - 21Jul2015 (Requires Java 7)

Issue | Description
:---- | :----------
[cryptacular-20]({{ site.issueURL }}20) | EncodingHashBean should support encoding salts
[cryptacular-18]({{ site.issueURL }}18) | RandomIdGenerator is not thread safe
[cryptacular-16]({{ site.issueURL }}16) | Improve exception handling

### Version 1.0 - 24Nov2014 (Requires Java 6)
Initial Release

