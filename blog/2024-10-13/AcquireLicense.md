# AcquireLicense

https://reference.dashif.org/dash.js/nightly/samples/drm/playready.html

~~~
mitmproxy --set stream_large_bodies=9m
~~~

even with the above, I cant seem to capture the license request with MitmProxy,
so just use HAR instead:

~~~
mitmproxy -r reference.dashif.org.har
~~~

<https://wikipedia.org/wiki/Replay_attack>

## Microsoft Edge

1. Settings and more
2. Settings
3. Privacy, search, and services
4. Clear browsing data, Clear browsing data now, Choose what to clear
5. Time range, all time
6. Cookies and other site data, Cached images and files
7. Clear now
