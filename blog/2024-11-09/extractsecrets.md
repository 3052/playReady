# extractsecrets

we need to do this:

~~~
msprcp> extractsecrets mspr_binary\libstd_cai_client_drm_msplayready.so
~~~

<https://security-explorations.com/materials/mspr_toolkit_README.md.txt>

but with an `.so` we have access to:

~~~
> play -i com.amazon.avod.thirdpartyclient -abi armeabi-v7a
details[8] = 0 USD
details[13][1][4] = 3.0.388.545
details[13][1][16] = Nov 8, 2024
details[13][1][17] = APK
details[13][1][82][1][1] = 5.0 and up
details[15][18] = http://www.amazon.com/gp/help/customer/display.html?nodeId=468496
downloads = 692.53 million
name = Amazon Prime Video
size = 51.13 megabyte
version code = 388000545
~~~

works:

~~~
com.amazon.avod.thirdpartyclient-388000545> rg -a CHAI\b
lib\armeabi-v7a\libAIVPlayReadyLicensing.so
�r5�&wv���|(ʖDG�gF37B��ʾ���l�]�R�7yޙ������?��%o�.@@�J      �����S/Eι�d�U���f���\�`&BR�~ױ�@8���+?�^lǰ�=g�y�3
. h|.f}'w�@ޠW�`�Lm嗲�{�        y������q7     ��<��O����R�o�'K`��xQ~h��� ����r�_�|��8ee����:U��+��~�(8j���S3�;}��>��B&�)�V�����6�0��N�U�"��X7CHAI\CERT�,X�LA������4���/��Ч?eۦ�oF�4�EjTO��,�G�:O�y�������`5,��������_��^�_��(��3�
~~~

fail:

~~~
> play -i tv.pluto.android
details[8] = 0 USD
details[13][1][4] = 5.49.0
details[13][1][16] = Oct 29, 2024
details[13][1][17] = APK APK APK APK
details[13][1][82][1][1] = 5.0 and up
details[15][18] = https://corporate.pluto.tv/privacy-policy/
downloads = 220.01 million
name = Pluto TV: Watch Free Movies/TV
size = 55.33 megabyte
version code = 410400212
~~~

fail:

~~~
> play -i com.tubitv -abi armeabi-v7a
details[8] = 0 USD
details[13][1][4] = 8.22.0
details[13][1][16] = Nov 4, 2024
details[13][1][17] = APK APK APK
details[13][1][82][1][1] = 9 and up
details[15][18] = https://tubitv.com/static/privacy
downloads = 173.99 million
name = Tubi: Free Movies & Live TV
size = 75.82 megabyte
version code = 851
~~~

fail:

~~~
> play -i com.hulu.plus
details[8] = 0 USD
details[13][1][4] = 5.9.1+15066-google
details[13][1][16] = Oct 25, 2024
details[13][1][17] = APK
details[13][1][82][1][1] = 7.1 and up
details[15][18] = https://www.hulu.com/privacy
downloads = 95.44 million
name = Hulu: Stream TV shows & movies
size = 19.62 megabyte
version code = 5015066
~~~

next:

~~~
> play -i com.hulu.livingroomplus -abi armeabi-v7a -leanback
details[8] = 0 USD
details[13][1][4] = 5EEC9D81P3.9.846
details[13][1][16] = Aug 6, 2024
details[13][1][17] = APK APK APK
details[13][1][82][1][1] = 4.4 and up
details[15][18] = https://www.hulu.com/privacy
downloads = 20.39 million
name = Hulu for Android TV
size = 47.67 megabyte
version code = 3009846
~~~

pass:

~~~
> rg -a CHAI\b
com.hulu.livingroomplus-config.armeabi_v7a-3009846\lib\armeabi-v7a\libwkf_support.so
163933:CHAI<CERT�
�U� ��?��^P�����N7䱣�k˱�/����l�RG�{��S4Hulu LLCWiiUWiiU�@`��ϡ-��s(�*��f���{��r!�#���g�DO��L��G��8��6�J�t���J���C��Lؓ��Lh#��C�ͪ�
�� �C�[��W'�o��YQy��h`M�X��,��
~~~

