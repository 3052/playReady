# helpers

~~~
helpers\Web.java:23: error: package sun.net.www is not visible
import sun.net.www.*;
              ^
(package sun.net.www is declared in module java.base, which does not export it
to the unnamed module)
~~~

and:

~~~
helpers\Web.java:112: error: cannot find symbol
            req_hdrs.add("TimeSeekRange.dlna.org", "npt=0-");
                    ^
  symbol:   method add(String,String)
  location: variable req_hdrs of type CleanMessageHeader
~~~
