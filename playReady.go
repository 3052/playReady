package playReady

import (
   "crypto/sha256"
   "encoding/base64"
   "strings"
)

func acquire_license_header_start() string {
   var b strings.Builder
   b.WriteString(`<AcquireLicense xmlns="http://schemas.microsoft.com/DRM/2007/03/protocols">`)
   b.WriteString(`<challenge><Challenge xmlns="http://schemas.microsoft.com/DRM/2007/03/protocols/messages">`)
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

func content_header(wrm_header string) string {
   var b strings.Builder
   b.WriteString("<ContentHeader>")
   b.WriteString(wrm_header)
   b.WriteString("</ContentHeader>")
   return b.String()
}

func encrypted_data_start() string {
   var b strings.Builder
   b.WriteString(`<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element">`)
   b.WriteString(`<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"></EncryptionMethod>`)
   return b.String()
}

func get_cipher_data(cipher_data string) string {
   var b strings.Builder
   b.WriteString("<CipherData><CipherValue>")
   b.WriteString(cipher_data)
   b.WriteString("</CipherValue></CipherData>")
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

func la_header_start() string {
   var b strings.Builder
   b.WriteString(`<LA xmlns="http://schemas.microsoft.com/DRM/2007/03/protocols" Id="SignedData" xml:space="preserve">`)
   b.WriteString(`<Version>1</Version>`)
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

func xml_header_start() string {
   var b strings.Builder
   b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
   b.WriteString(`<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`)
   b.WriteString(` xmlns:xsd="http://www.w3.org/2001/XMLSchema"`)
   b.WriteString(` xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">`)
   return b.String()
}

type device struct {
   cert certificate
   cur_dev *device
   mac string
   serial string
}

func (d device) changed() bool {
   if d.cur_dev == nil {
      return true
   }
   if d.cur_dev.mac != d.mac {
      return true
   }
   if d.cur_dev.serial != d.serial {
      return true
   }
   return false
}
