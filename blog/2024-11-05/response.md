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

~~~js
function parseXMRLicense(xmr, offset) {
   XMRStatic.offset = offset;
   var list = new Array();
   var headerObject = new playready.XMRHeader();
   headerObject.parse(xmr);
   list.push(headerObject);
   while (XMRStatic.offset < xmr.length) {
       XMRStatic.setPostOffset(0);
       var peekOffset = XMRStatic.offset;
       var flags = readWORD(xmr);
       var type = readWORD(xmr);
       XMRStatic.offset = peekOffset;
       var xmrObject = new playready.XMRObject();
       var unknownType = false;
       switch (type) {
           case playready.XMRObjectType.OuterContainer:
               xmrObject = new playready.OuterContainer();
               break;
           case playready.XMRObjectType.GlobalPolicy:
               xmrObject = new playready.GlobalPolicyContainer();
               break;
           case playready.XMRObjectType.PlaybackPolicy:
               xmrObject = new playready.PlaybackPolicyContainer();
               break;
           case playready.XMRObjectType.PlayEnabler:
               xmrObject = new playready.PlayEnablerContainer();
               break;
           case playready.XMRObjectType.PlayEnablerType:
               xmrObject = new playready.PlayEnablerType();
               break;
           case playready.XMRObjectType.DomainRestriction:
               xmrObject = new playready.DomainRestrictionObject();
               break;
           case playready.XMRObjectType.IssueDate:
               xmrObject = new playready.IssueDateObject();
               break;
           case playready.XMRObjectType.RevInfoVersion:
               xmrObject = new playready.RevInfoVersionObject();
               break;
           case playready.XMRObjectType.SecurityLevel:
               xmrObject = new playready.SecurityLevelObject();
               break;
           case playready.XMRObjectType.EmbeddedLicenseSettings:
               xmrObject = new playready.EmbeddedLicenseSettingsObject();
               break;
           case playready.XMRObjectType.KeyMaterialContainer:
               xmrObject = new playready.KeyMaterialContainerObject();
               break;
           case playready.XMRObjectType.ContentKey:
               xmrObject = new playready.ContentKeyObject();
               break;
           case playready.XMRObjectType.ECCKey:
               xmrObject = new playready.ECCKeyObject();
               break;
           case playready.XMRObjectType.XMRSignature:
               xmrObject = new playready.XMRSignatureObject();
               break;
           case playready.XMRObjectType.RightsSettingObject:
               xmrObject = new playready.XMRRightsSettingsObject();
               break;
           case playready.XMRObjectType.OutputProtectionLevelRestriction:
               xmrObject = new playready.XMROutputProtectionLevelRestrictionObject();
               break;
           case playready.XMRObjectType.ExpirationRestriction:
               xmrObject = new playready.ExpirationRestrictionObject();
               break;
           case playready.XMRObjectType.RealTimeExpirationRestriction:
               xmrObject = new playready.XMRRealTimeExpirationRestriction();
               break;
           case playready.XMRObjectType.UplinkKIDObject:
               xmrObject = new playready.XMRUplinkKIDObject();
               break;
           case playready.XMRObjectType.ExplicitDigitalVideoOutputProtection:
               xmrObject = new playready.ExplicitDigitalVideoOutputProtectionObject();
               break;
           case playready.XMRObjectType.DigitalVideoOutputRestriction:
               xmrObject = new playready.DigitalVideoOutputRestrictionObject();
               break;
           case playready.XMRObjectType.ExplicitDigitalAudioOutputProtection:
               xmrObject = new playready.ExplicitDigitalAudioOutputProtectionObject();
               break;
           case playready.XMRObjectType.DigitalAudioOutputRestriction:
               xmrObject = new playready.DigitalAudioOutputRestrictionObject();
               break;
           case playready.XMRObjectType.SecureStopRestriction:
               xmrObject = new playready.SecureStopRestrictionObject();
               break;
           case playready.XMRObjectType.ExpirationAfterFirstPlayRestriction:
               xmrObject = new playready.ExpirationAfterFirstPlayRestrictionObject();
               break;
           case playready.XMRObjectType.RemovalDateObject:
               xmrObject = new playready.RemovalDateObject();
               break;
           case playready.XMRObjectType.GracePeriodObject:
               xmrObject = new playready.GracePeriodObject();
               break;
           case playready.XMRObjectType.SourceIdObject:
               xmrObject = new playready.SourceIdObject();
               break;
           case playready.XMRObjectType.MeteringRestrictionObject:
               xmrObject = new playready.MeteringRestrictionObject();
               break;
           case playready.XMRObjectType.PolicyMetadataObject:
               xmrObject = new playready.PolicyMetadataObject();
               break;
           case playready.XMRObjectType.ExplicitAnalogVideoOutputProtectionContainer:
               xmrObject = new playready.ExplicitAnalogVideoOutputProtectionContainer();
               break;
           case playready.XMRObjectType.AnalogVideoOutputConfigurationRestriction:
               xmrObject = new playready.AnalogVideoOutputConfigurationRestriction();
               break;
           case playready.XMRObjectType.AuxiliaryKeyObject:
               xmrObject = new playready.AuxiliaryKeyObject();
               break;
           case playready.XMRObjectType.UplinkKeyObject3:
               xmrObject = new playready.UplinkKeyObject3();
               break;
           case playready.XMRObjectType.CopyObject:
               xmrObject = new playready.CopyObject();
               break;
           case playready.XMRObjectType.CopyEnablerContainerObject:
               xmrObject = new playready.CopyEnablerContainerObject();
               break;
           case playready.XMRObjectType.CopyEnablerObject:
               xmrObject = new playready.CopyEnablerObject();
               break;
           case playready.XMRObjectType.CopyCountRestrictionObject:
               xmrObject = new playready.CopyCountRestrictionObject();
               break;
           case playready.XMRObjectType.MoveObject:
               xmrObject = new playready.MoveObject();
               break;
           case playready.XMRObjectType.ReadContainerObject:
               xmrObject = new playready.ReadContainerObject();
               break;
           case playready.XMRObjectType.ExecuteContainerObject:
               xmrObject = new playready.ExecuteContainerObject();
               break;
           case playready.XMRObjectType.RestrictedSourceIdObject:
               xmrObject = new playready.RestrictedSourceIdObject();
               break;
           default:
               xmrObject = new playready.UnknownObject();
               unknownType = true;
               break;
       }
       xmrObject.parse(xmr);
       list.push(xmrObject);
       XMRStatic.depthByteCount[XMRStatic.currentDepth] += xmrObject.Length;
       xmrObject.Debug = XMRStatic.depthByteCount.toString();
       for (var d = XMRStatic.currentDepth; d >= 0; d--) {
           XMRStatic.depthByteCount[d] -= (XMRStatic.offset - peekOffset);
       }
       xmrObject.Depth = XMRStatic.currentDepth;
       if (XMRStatic.depthByteCount[XMRStatic.currentDepth] > 0) {
           XMRStatic.currentDepth += 1;
       }
       else if (XMRStatic.currentDepth > 0) {
           for (var e = 0; e < XMRStatic.depthByteCount.length; e++) {
               if (XMRStatic.depthByteCount[e] === 0) {
                   XMRStatic.currentDepth = e;
                   break;
               }
           }
       }
   }
   return list;
}
~~~
