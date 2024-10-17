package playReady

import (
   "crypto/sha256"
   "encoding/base64"
   "strings"
)

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

func (d device) get_cert() certificate {
   set := func() bool {
      if d.cert == nil {
         return true
      }
      if d.changed() {
         return true
      }
      if d.cert.get_seclevel() != cur_SL() {
         return true
      }
      return false
   }
   if set() {
      d.cert=new BCert.Certificate();
      byte random[]=ECC.bi_bytes(ECC.random(128));
      d.cert.set_random(random);
      d.cert.set_seclevel(cur_SL());
      d.cert.set_uniqueid(get_uniqueid());
      d.cert.set_prvkey_sign(sign_key.prv_bytes());
      d.cert.set_pubkey_sign(sign_key.pub_bytes());
      d.cert.set_pubkey_enc(enc_key.pub_bytes());
   }
   return d.cert;
}

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
