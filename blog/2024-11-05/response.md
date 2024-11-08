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

then:

~~~js
function Run(licensesCol, target) {
   if (target === void 0) { target = "output"; }
   document.getElementById(target).innerHTML = "";
   if (licensesCol.length === 0) {
       document.getElementById(target).innerHTML = "No licenses found!";
   }
   try {
       for (var i = 0; i < licensesCol.length; i++) {
           var license = licensesCol[i];
           var decodedData = window.atob(license);
           var dataLength = decodedData.length;
           var licenseData = new Uint8Array(new ArrayBuffer(dataLength));
           for (var i2 = 0; i2 < dataLength; i2++) {
               licenseData[i2] = decodedData.charCodeAt(i2);
           }
           var xmrObjects = playready.xmrparser.parseXMRLicense(licenseData, 0);
           if (licensesCol.length > 1) {
               var divLicenseLabel = document.createElement("div");
               var kid = playready.xmrparser.getKeyID(xmrObjects);
               document.getElementById(target).appendChild(divLicenseLabel);
               divLicenseLabel.classList.add("licenseLabel");
               divLicenseLabel.innerHTML = "<span class='licenseLabelIcon'>\u23F5</span> License " + (i + 1) + " <code>" + kid.toString() + "</code>";
               divLicenseLabel["license"] = i;
               divLicenseLabel.addEventListener('click', function (ev) {
                   var index = ev.currentTarget["license"];
                   var expanded = ev.currentTarget["expanded"] === true;
                   var elem = document.getElementById("divLicense_" + index);
                   var icon = ev.currentTarget["querySelector"](".licenseLabelIcon");
                   expanded = !expanded;
                   if (expanded) {
                       elem.classList.remove("none");
                       icon.innerHTML = "\u23F7";
                   }
                   else {
                       elem.classList.add("none");
                       icon.innerHTML = "\u23F5";
                   }
                   ev.currentTarget["expanded"] = expanded;
               });
           }
           var divLicenseWrapper = document.createElement("div");
           document.getElementById(target).appendChild(divLicenseWrapper);
           divLicenseWrapper.classList.add("license");
           divLicenseWrapper.id = "divLicense_" + i;
           if (licensesCol.length > 1) {
               divLicenseWrapper.classList.add("none");
           }
           xmrObjects.forEach(function (xmrObject) {
               var objectAnnotations = xmrObject.getObjectAnnotations();
               var divTAGWrapper = document.createElement("div");
               divLicenseWrapper.appendChild(divTAGWrapper);
               divTAGWrapper.classList.add("xmrobjectwrapper");
               var divTAG = document.createElement("div");
               divTAGWrapper.appendChild(divTAG);
               divTAG.classList.add("xmrobject");
               divTAG.classList.add(playready.VerboseLevel[objectAnnotations.VerboseLevel]);
               divTAG.style.marginLeft = (20 * xmrObject.Depth) + "px";
               var divHeader = document.createElement("div");
               divHeader.classList.add('xmrobjectheader');
               var spanName = document.createElement('span');
               divHeader.appendChild(spanName);
               spanName.innerHTML = objectAnnotations.PrintName;
               var spanVal = document.createElement('span');
               spanVal.classList.add(playready.VerboseLevel[playready.VerboseLevel.verbose]);
               divHeader.appendChild(spanVal);
               spanVal.innerHTML = " - <code>" + numberToHex(xmrObject["Type"], 4) + "</code>";
               divTAG.appendChild(divHeader);
               for (var property in xmrObject) {
                   if (xmrObject.hasOwnProperty(property)) {
                       if (typeof objectAnnotations.FieldAnnotations[property] !== "undefined") {
                           var annon = objectAnnotations.FieldAnnotations[property];
                           var divPair = document.createElement("div");
                           divPair.classList.add("propwrapper");
                           divTAG.appendChild(divPair);
                           divPair.classList.add(playready.VerboseLevel[annon.VerboseLevel]);
                           spanName = document.createElement('span');
                           spanName.classList.add("propname");
                           divPair.appendChild(spanName);
                           spanName.innerHTML = annon.PrintName !== "" ? annon.PrintName : property;
                           spanVal = document.createElement('span');
                           spanVal.classList.add("propval");
                           divPair.appendChild(spanVal);
                           spanVal.innerHTML = "<code>" + renderProperty(annon.DataFormatType, xmrObject[property], 0) + "</code>";
                           spanName["xmrValue"] = xmrObject[property];
                           spanName["DataFormatType"] = annon.DataFormatType;
                           spanName["xmrFormatIndex"] = 0;
                           spanName["xmrValueSpan"] = spanVal;
                           spanName.onclick = cycleValueFormat;
                       }
                       else {
                           var divPair = document.createElement("div");
                           divPair.classList.add("propwrapper");
                           divTAG.appendChild(divPair);
                           divPair.classList.add(playready.VerboseLevel[playready.VerboseLevel.normal]);
                           spanName = document.createElement('span');
                           spanName.classList.add("propname");
                           divPair.appendChild(spanName);
                           spanName.innerHTML = property;
                           spanVal = document.createElement('span');
                           spanVal.classList.add("propval");
                           divPair.appendChild(spanVal);
                           spanVal.innerHTML = "<code style='background:#CCCCCC'>" + xmrObject[property].toString() + "</code>";
                       }
                   }
               }
           });
       }
       verboseShown = true;
       playready.test.toggleVisibility('verbose');
   }
   catch (e) {
       document.getElementById(target).innerHTML = "license parsing error";
   }
}
~~~

https://testweb.playready.microsoft.com/js/parser/XMRParser.js
