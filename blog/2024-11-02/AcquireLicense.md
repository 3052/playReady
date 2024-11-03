# AcquireLicense

~~~java
public static String SIGNED_INFO(String digest)
~~~

called by:

~~~java
public static String build_license_request(Device dev, String wrmheader, String
nonce, String keydata, String cipherdata) throws Throwable
~~~

called by:

~~~java
public static String get_license_request(Device dev, String wrmheader) throws
Throwable
~~~

called by:

~~~
src\mod\mspr\Asset.java
242:     String req=MSPR.get_license_request(curdev,wrmhdr);
~~~
