package playReady

import (
   "crypto/sha256"
   "encoding/base64"
   "strings"
)

BCert.Certificate get_cert() {
   if ((cert==null)||changed()||((cert!=null)&&(cert.get_seclevel()!=cur_SL()))) {
      cert=new BCert.Certificate();
      if (MSPR.fixed_identity()) {
         byte random[]=Utils.parse_hex_string("bee27cbf64aac0c94cd60ff28a05e1b4");
         cert.set_random(random);
         cert.set_seclevel(cur_SL());
         cert.set_uniqueid(get_uniqueid());
         cert.set_prvkey_sign(sign_key.prv_bytes());
         cert.set_pubkey_sign(sign_key.pub_bytes());
         cert.set_pubkey_enc(enc_key.pub_bytes());
      } else {
         byte random[]=ECC.bi_bytes(ECC.random(128));
         cert.set_random(random);
         cert.set_seclevel(cur_SL());
         cert.set_uniqueid(get_uniqueid());
         cert.set_prvkey_sign(sign_key.prv_bytes());
         cert.set_pubkey_sign(sign_key.pub_bytes());
         cert.set_pubkey_enc(enc_key.pub_bytes());
      }
   }
   return cert;
}

type device struct{}

func (d device) build_signature(data string) string {
   BCert.Certificate cert=d.get_cert();
   byte prvkey_sign[]=cert.get_prvkey_for_signing();
   BigInteger prv_sign_key=ECC.make_bi(prvkey_sign,0,0x20);
   byte signature_bytes[]=Crypto.ecdsa(data.getBytes(),prv_sign_key);
   String signature=Crypto.base64_encode(signature_bytes);
   byte pubkey_sign[]=cert.get_pubkey_for_signing();
   String pubkey=Crypto.base64_encode(pubkey_sign);
   String xml_req="";
   xml_req+=SIGNATURE(signature);
   xml_req+=PUBLIC_KEY(pubkey);
   xml_req+=SIGNATURE_END();
   return xml_req;
}

func build_license_request(
   device dev, wrm_header, nonce, key_data, cipher_data string,
) string {
   var b strings.Builder
   b.WriteString(xml_header_start())
   b.WriteString("<soap:Body>")
   b.WriteString(acquire_license_header_start())
   digest_content := build_digest_content(
      wrm_header, nonce, key_data, cipher_data,
   )
   b.WriteString(digest_content)
   digest_bytes := sha256.Sum256([]byte(digest_content))
   digest := base64.StdEncoding.EncodeToString(digest_bytes)
   b.WriteString(`<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">`)
   signed_info := get_signed_info(digest)
   b.WriteString(signed_info)
   //////////////////////////////////////////////////////////////////////////////
   String signature=build_signature(dev,signed_info);
   b+=signature;
   b+=ACQUIRE_LICENSE_HEADER_END();
   b+=SOAP_BODY_END();
   b+=XML_HEADER_END();
   return b.String()
}

func get_signed_info(digest string) string {
   var b strings.Builder
   b.WriteString(`<SignedInfo xmlns="http://www.w3.org/2000/09/xmldsig#">`)
   b.WriteString(`<CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315">`)
   b.WriteString("</CanonicalizationMethod>")
   b.WriteString(`<SignatureMethod Algorithm="http://schemas.microsoft.com/DRM/2007/03/protocols#ecdsa-sha256">`)
   b.WriteString(`</SignatureMethod><Reference URI="#SignedData">`)
   b.WriteString(`<DigestMethod Algorithm="http://schemas.microsoft.com/DRM/2007/03/protocols#sha256">`)
   b.WriteString("</DigestMethod><DigestValue>")
   b.WriteString(digest)
   b.WriteString("</DigestValue></Reference></SignedInfo>")
   return b.String()
}

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

func get_cipher_data(string cipher_data) string {
   var b strings.Builder
   b.WriteString("<CipherData><CipherValue>")
   b.WriteString(cipher_data)
   b.WriteString("</CipherValue></CipherData>")
   return b.String()
}

func build_digest_content(wrm_header, nonce, key_data, cipher_data string) string {
   var b strings.Builder
   b.WriteString(la_header_start())
   b.WriteString(content_header(wrm_header))
   b.WriteString("<ClientInfo><ClientVersion>1.2.0.1404</ClientVersion></ClientInfo>")
   b.WriteString(license_nonce(nonce))
   b.WriteString(encrypted_data_start())
   b.WriteString(key_info(key_data))
   b.WriteString(get_cipher_data(cipher_data))
   b.WriteString("</EncryptedData></LA>")
   return b.String()
}
