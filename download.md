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

### Version 1.2.1 - 10Jul2017 (Requires Java 8)

Issue | Description
:---- | :----------
[cryptacular-36]({{ site.issueURL }}36) | Upgrade Bouncy Castle to version 1.57

### Version 1.2.0 - 10Aug2016 (Requires Java 8)

Issue | Description
:---- | :----------
[cryptacular-26]({{ site.issueURL }}26) | Upgrade Bouncy Castle to version 1.54
[cryptacular-23]({{ site.issueURL }}23) | EncodingHashBean convenience constructor

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

