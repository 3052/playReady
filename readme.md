# playReady

https://wikipedia.org/wiki/PlayReady

this seems to be blocked until we can find this file:

~~~
msprcp> extractsecrets mspr_binary\libstd_cai_client_drm_msplayready.so
~~~

<https://security-explorations.com/materials/mspr_toolkit_README.md.txt>

we will know if we have the right file if it contains:

~~~
__img_zgp_end
~~~

> You want to look for known devices or apps that license PR, like the Amazon
> Prime app for Android. And look for any .so that could match this name, but
> then again they're not implemented/used the same way.

https://play.google.com/store/apps/details?id=com.amazon.avod.thirdpartyclient

~~~
> play -i com.amazon.avod.thirdpartyclient -abi armeabi-v7a
details[8] = 0 USD
details[13][1][4] = 3.0.383.445
details[13][1][16] = Oct 10, 2024
details[13][1][17] = APK
details[13][1][82][1][1] = 5.0 and up
details[15][18] = http://www.amazon.com/gp/help/customer/display.html?nodeId=468496
downloads = 686.22 million
name = Amazon Prime Video
size = 49.92 megabyte
version code = 383000445
~~~

then:

~~~
lib\armeabi-v7a\libAIVPlayReadyLicensing.so
~~~

secrets\z1 (PlayReady private ECC group key):

~~~
assets\PlayReady\zgpriv.dat
~~~

secrets\g1 (PlayReady binary group certificate):

~~~
assets\PlayReady\bgroupcert.dat
~~~

## history

- <https://security-explorations.com/samples/mspr_leak_screenshot3.png>
- https://files.catbox.moe/8iz2qk.pdb
- https://reddit.com/r/ReverseEngineering/comments/1dnicyh
- https://seclists.org/fulldisclosure/2024/Jun/7
- https://security-explorations.com/microsoft-warbird-pmp.html

## ICE\_REPRO.zip

- <http://4a.si/dir/ICE_REPRO.zip>
- <http://web.archive.org/sendvsfeedback2-download.azurewebsites.net/api/fileBlob/file?name=B0cde770200a945109437927ba3fe4d67638537352993712632_ICE_REPRO.zip&tid=0cde770200a945109437927ba3fe4d67638537352993712632>
