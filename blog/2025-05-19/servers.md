# servers

- <https://refapp.hbbtv.org/dash/test_dashjs_sl3000.html?video=sl3000>
- http://playready.directtaps.net/pr/svc/rightsmanager.asmx?PlayRight=1&SecurityLevel=2000
- https://reference.dashif.org/dash.js/nightly/samples/drm/playready.html
- https://sample.pallycon.com/demo/drm-demo/shaka
- https://testweb.playready.microsoft.com
- https://testweb.playready.microsoft.com/Tool/PlayerHAS

~~~
mitmproxy --set stream_large_bodies=9m
~~~

even with the above, I cant seem to capture the license request with MitmProxy,
so just use HAR instead:

~~~
mitmproxy -r reference.dashif.org.har
~~~

<https://wikipedia.org/wiki/Replay_attack>

## how to get X-Axdrm-Message?

its in HTML response body:

~~~js
const protData = {
    "com.microsoft.playready": {
        "serverURL": "https://drm-playready-licensing.axtest.net/AcquireLicense",
        "httpRequestHeaders": {
            "X-AxDRM-Message": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ2ZXJz..."
        }
    }
};
~~~

## Microsoft Edge

1. Settings and more
2. Settings
3. Privacy, search, and services
4. Clear browsing data, Clear browsing data now, Choose what to clear
5. Time range, all time
6. Cookies and other site data, Cached images and files
7. Clear now
