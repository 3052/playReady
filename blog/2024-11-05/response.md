# response

~~~
src\mod\mspr\Asset.java
242:     String req=MSPR.get_license_request(curdev,wrmhdr);
~~~

`license_xml` is byte slice:

~~~java
license=new License(license_xml);
~~~

https://testweb.playready.microsoft.com/Tool/LicenseInspector

~~~html
<textarea class="m-2 col" wrap="hard"
oninput="playready.test.tryParseXMRDirect()" id="xmrInput"></textarea>
~~~

https://testweb.playready.microsoft.com/js/parser/XMRRender.js

~~~js
function tryParseXMRDirect() {
   var value = document.getElementById("xmrInput").value.trim();
   if (value === "") {
       playready.test.Run(Data.licenses);
   }
   else {
       var testlicensesInput = [];
       testlicensesInput[0] = value;
       playready.test.Run(testlicensesInput);
   }
}
~~~
