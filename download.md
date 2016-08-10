---
layout: default
title: Download Cryptacular
---
Download the latest version which includes source code, classes, javadocs, and tests in zip or tar.gz format.

* [TAR](/downloads/{{ site.version }}/cryptacular-{{ site.version }}-dist.tar.gz)
* [ZIP](/downloads/{{ site.version }}/cryptacular-{{ site.version }}-dist.zip)

Individual artifacts are available in the [Maven Central Repository](http://repo1.maven.org/maven2/org/cryptacular/cryptacular/).
If you would like to use this project in your maven build, include the following in your pom.xml:
{% highlight xml %}
<dependencies>
  <dependency>
    <groupId>org.cryptacular</groupId>
    <artifactId>cryptacular</artifactId>
    <version>{{ site.version }}</version>
  </dependency>
<dependencies>
{% endhighlight %}

