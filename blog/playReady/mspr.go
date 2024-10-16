package playReady

import "strings"

func xml_header_start() string {
   var b strings.Builder
   b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
   b.WriteString(`<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`)
   b.WriteString(` xmlns:xsd="http://www.w3.org/2001/XMLSchema"`)
   b.WriteString(` xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">`)
   return b.String()
}

func acquire_license_header_start() string {
   var b strings.Builder
   b.WriteString(`<AcquireLicense xmlns="http://schemas.microsoft.com/DRM/2007/03/protocols">`)
   b.WriteString(`<challenge><Challenge xmlns="http://schemas.microsoft.com/DRM/2007/03/protocols/messages">`)
   return b.String()
}

func la_header_start() string {
   var b strings.Builder
   b.WriteString(`<LA xmlns="http://schemas.microsoft.com/DRM/2007/03/protocols" Id="SignedData" xml:space="preserve">`)
   b.WriteString(`<Version>1</Version>`)
   return b.String()
}

func content_header(wrm_header string) string {
   var b strings.Builder
   b.WriteString("<ContentHeader>")
   b.WriteString(wrm_header)
   b.WriteString("</ContentHeader>")
   return b.String()
}

func license_nonce(nonce string) string {
   var b strings.Builder
   b.WriteString("<LicenseNonce>")
   b.WriteString(nonce)
   b.WriteString("</LicenseNonce>")
   // not sure of this
   b.WriteString("  ")
   return b.String()
}

func encrypted_data_start() string {
   var b strings.Builder
   b.WriteString(`<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">`)
   b.WriteString(`<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></EncryptionMethod>`)
   return b.String()
}

func key_info(key_data string) string {
   var b strings.Builder
   b.WriteString(`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">`)
   b.WriteString(`<EncryptedKey xmlns="http://www.w3.org/2001/04/xmlenc#">`)
   b.WriteString(`<EncryptionMethod Algorithm="http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256"></EncryptionMethod>`)
   b.WriteString(`<KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">`)
   b.WriteString("<KeyName>WMRMServer</KeyName>")
   b.WriteString("</KeyInfo><CipherData><CipherValue>")
   b.WriteString(key_data)
   b.WriteString("</CipherValue></CipherData></EncryptedKey></KeyInfo>")
   return b.String()
}

func build_digest_content(wrm_header, nonce, key_data, cipherdata string) string {
   var b strings.Builder
   b.WriteString(la_header_start())
   b.WriteString(content_header(wrm_header))
   b.WriteString("<ClientInfo><ClientVersion>1.2.0.1404</ClientVersion></ClientInfo>")
   b.WriteString(license_nonce(nonce))
   b.WriteString(encrypted_data_start())
   //////////////////////////////////////////////////////////////////////////////
   b+=KEY_INFO(key_data);
   b+=CIPHER_DATA(cipherdata);
   b+=ENCRYPTED_DATA_END();
   b+=LA_HEADER_END();
   return b.String()
}

func build_license_request(
   Device dev, wrm_header, nonce, key_data, cipherdata string,
) string {
   var xml_req strings.Builder
   xml_req.WriteString(xml_header_start())
   xml_req.WriteString("<soap:Body>")
   xml_req.WriteString(acquire_license_header_start())
   //////////////////////////////////////////////////////////////////////////////
   String digest_content=build_digest_content(
      wrm_header, nonce, key_data, cipherdata,
   );
   xml_req+=digest_content;
   byte digest_bytes[]=Crypto.SHA256(digest_content.getBytes());
   String digest=Crypto.base64_encode(digest_bytes);
   xml_req+=SIGNATURE_START();  
   String signed_info=SIGNED_INFO(digest);
   xml_req+=signed_info;
   if (fixed_identity()) {
      // random k for ECC signing (XML signature generation)
      BigInteger r=ECC.make_bi(Utils.reverse_hex_string("2238f95e2961b5eea60a64925b14d7fa42d4ba11eb99d7cb956aa056838b6d38"));
      ECC.set_random(r);
   }
   String signature=build_signature(dev,signed_info);
   xml_req+=signature;
   xml_req+=ACQUIRE_LICENSE_HEADER_END();
   xml_req+=SOAP_BODY_END();
   xml_req+=XML_HEADER_END();
   return xml_req.String()
}
