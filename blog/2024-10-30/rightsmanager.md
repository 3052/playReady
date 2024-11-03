# rightsmanager

~~~
Today at 7:33 PM

curl --location 'https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(msg%3Aclientinfo)' \
--header 'SOAPAction: http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense' \
--header 'Content-Type: text/xml' \
--data ''

post xml to this endpoint to get details of a challenge.
~~~
