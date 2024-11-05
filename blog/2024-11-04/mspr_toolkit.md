# mspr\_toolkit

<https://security-explorations.com/materials/mspr_toolkit_README.md.txt>

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

secrets\g1 (PlayReady binary group certificate):

~~~
assets\PlayReady\bgroupcert.dat
~~~

secrets\z1 (PlayReady private ECC group key):

~~~
assets\PlayReady\zgpriv.dat
~~~
