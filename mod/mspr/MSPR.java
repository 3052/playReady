/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package mod.mspr;

import agsecres.tool.*;
import agsecres.helper.*;
import java.lang.*;
import java.io.*;
import java.math.*;
import java.security.*;
import java.util.*;
import java.math.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class MSPR {
   public static final String WMRMECC256PubKey = "C8B6AF16EE941AADAA5389B4AF2C10E356BE42AF175EF3FACE93254E7B0B3D9B982B27B5CB2341326E56AA857DBFD5C634CE2CF9EA74FCA8F2AF5957EFEEA562";

   //security levels for devices / content access
   public static final int SL150 = 150;
   public static final int SL2000 = 2000;
   public static final int SL3000 = 3000;

   public static final String GROUP_CERT = "g1";
   public static final String GROUP_CERT_PRV_KEY = "z1";

   public static final int AES_KEY_SIZE = 0x10;
   public static final int NONCE_SIZE = 0x10;

   private static XmlKey xmlkey;

   private static ECC.ECPoint WMRMpubkey;

   static {
      byte data[] = Utils.parse_hex_string(WMRMECC256PubKey);
      WMRMpubkey = new ECC.ECPoint(data);
   }

   public static boolean fixed_identity() {
      return Vars.get_int("MSPR_DEBUG") == 1;
   }

   public static String SL2string(int level) {
      switch (level) {
      case SL150:
         return "SL150";
      case SL2000:
         return "SL2000";
      case SL3000:
         return "SL3000";
      }

      return "" + level;
   }

   public static int string2SL(String s) {
      if (s != null) {
         if (s.equals("SL150")) return SL150;
         else
         if (s.equals("SL2000")) return SL2000;
         else
         if (s.equals("SL3000")) return SL3000;
      }

      return -1;
   }

   public static class XmlKey {
      ECC.ECKey shared_point;
      BigInteger shared_key;

      byte aes_iv[];
      byte aes_key[];

      public XmlKey() {
         shared_point = new ECC.ECKey();
         shared_key = pub().x();
      }

      public ECC.ECPoint pub() {
         return shared_point.pub();
      }

      public BigInteger prv() {
         return shared_point.prv();
      }

      public void setup_aes_key() {
         byte shared_data[] = ECC.bi_bytes(shared_key);

         aes_iv = new byte[AES_KEY_SIZE];
         aes_key = new byte[AES_KEY_SIZE];

         System.arraycopy(shared_data, 0, aes_iv, 0, AES_KEY_SIZE);
         System.arraycopy(shared_data, 0x10, aes_key, 0, AES_KEY_SIZE);
      }

      public void set_aes_iv(byte iv[]) {
         if (iv.length != AES_KEY_SIZE) ERR.log("Invalid AES IV length");

         aes_iv = iv;
      }

      public void set_aes_key(byte key[]) {
         if (key.length != AES_KEY_SIZE) ERR.log("Invalid AES key length");

         aes_key = key;
      }

      public byte[] aes_iv() {
         if (aes_iv == null) {
            setup_aes_key();
         }

         return aes_iv;
      }

      public byte[] aes_key() {
         if (aes_key == null) {
            setup_aes_key();
         }

         return aes_key;
      }

      public void print() {
         System.out.println("XML key (AES/CBC)");
         System.out.printf(
            "iv %s\n", HexFormat.of().formatHex(aes_iv())
         );
         System.out.printf(
            "key %s\n", HexFormat.of().formatHex(aes_key())
         );
      }

      public byte[] bytes() {
         byte data[] = new byte[2 * AES_KEY_SIZE];
         System.arraycopy(aes_iv(), 0, data, 0, AES_KEY_SIZE);
         System.arraycopy(aes_key(), 0, data, AES_KEY_SIZE, AES_KEY_SIZE);

         return data;
      }
   }

   public static XmlKey getXmlKey() {
      if (xmlkey == null) {
         xmlkey = new XmlKey();
      }

      return xmlkey;
   }

   public static String XML_HEADER_START() {
      String s = "";

      s += "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
      s += "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" ";
      s += "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" ";
      s += "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">";

      return s;
   }

   public static String SOAP_BODY_START() {
      return "<soap:Body>";
   }

   public static String ACQUIRE_LICENSE_HEADER_START() {
      String s = "";
      s += "<AcquireLicense xmlns=\"http://schemas.microsoft.com/DRM/2007/03/protocols\">";
      s += "<challenge><Challenge xmlns=\"http://schemas.microsoft.com/DRM/2007/03/protocols/messages\">";

      return s;
   }

   public static String LA_HEADER_START() {
      String s = "";

      s += "<LA xmlns=\"http://schemas.microsoft.com/DRM/2007/03/protocols\" Id=\"SignedData\" xml:space=\"preserve\">";
      s += "<Version>1</Version>";

      return s;
   }

   public static String CONTENT_HEADER(String wrmheader) {
      String s = "";

      s += "<ContentHeader>";
      s += wrmheader;
      s += "</ContentHeader>";

      return s;
   }

   public static String CLIENT_INFO() {
      return "<ClientInfo><ClientVersion>1.2.0.1404</ClientVersion></ClientInfo>";
   }

   public static String LICENSE_NONCE(String nonce) {
      String s = "";

      s += "<LicenseNonce>";
      s += nonce;
      s += "</LicenseNonce>";

      //not sure of this
      s += "  ";

      return s;
   }

   public static String ENCRYPTED_DATA_START() {
      String s = "";

      s += "<EncryptedData xmlns=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">";
      s += "<EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"></EncryptionMethod>";

      return s;
   }

   public static String KEY_INFO(String keydata) {
      String s = "";

      s += "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";
      s += "<EncryptedKey xmlns=\"http://www.w3.org/2001/04/xmlenc#\">";
      s += "<EncryptionMethod Algorithm=\"http://schemas.microsoft.com/DRM/2007/03/protocols#ecc256\"></EncryptionMethod>";
      s += "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";
      s += "<KeyName>WMRMServer</KeyName>";
      s += "</KeyInfo>";
      s += "<CipherData>";
      s += "<CipherValue>";
      s += keydata;
      s += "</CipherValue>";
      s += "</CipherData>";
      s += "</EncryptedKey>";
      s += "</KeyInfo>";

      return s;
   }

   public static String CIPHER_DATA(String cipherdata) {
      String s = "";

      s += "<CipherData><CipherValue>";
      s += cipherdata;
      s += "</CipherValue></CipherData>";

      return s;
   }

   public static String ENCRYPTED_DATA_END() {
      String s = "";

      s += "</EncryptedData>";

      return s;
   }

   public static String LA_HEADER_END() {
      String s = "";

      s += "</LA>";

      return s;
   }

   public static String SIGNED_INFO(String digest) {
      String s = "";

      s += "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";
      s += "<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\">";
      s += "</CanonicalizationMethod>";
      s += "<SignatureMethod Algorithm=\"http://schemas.microsoft.com/DRM/2007/03/protocols#ecdsa-sha256\">";
      s += "</SignatureMethod>";
      s += "<Reference URI=\"#SignedData\">";
      s += "<DigestMethod Algorithm=\"http://schemas.microsoft.com/DRM/2007/03/protocols#sha256\">";
      s += "</DigestMethod>";
      s += "<DigestValue>";
      s += digest;
      s += "</DigestValue>";
      s += "</Reference>";
      s += "</SignedInfo>";

      return s;
   }

   public static String SIGNATURE_START() {
      String s = "";

      s += "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";

      return s;
   }

   public static String SIGNATURE(String signature) {
      String s = "";

      s += "<SignatureValue>";
      s += signature;
      s += "</SignatureValue>";

      return s;
   }

   public static String PUBLIC_KEY(String pubkey) {
      String s = "";

      s += "<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">";
      s += "<KeyValue><ECCKeyValue><PublicKey>";
      s += pubkey;
      s += "</PublicKey>";
      s += "</ECCKeyValue>";
      s += "</KeyValue>";
      s += "</KeyInfo>";

      return s;
   }

   public static String SIGNATURE_END() {
      String s = "";

      s += "</Signature>";

      return s;
   }

   public static String ACQUIRE_LICENSE_HEADER_END() {
      String s = "";

      s += "</Challenge></challenge></AcquireLicense>";

      return s;
   }

   public static String SOAP_BODY_END() {
      String s = "";

      s += "</soap:Body>";

      return s;
   }

   public static String XML_HEADER_END() {
      String s = "";

      s += "</soap:Envelope>";

      return s;
   }

   public static String CERT_CHAIN_START() {
      String s = "";

      s += "<Data><CertificateChains><CertificateChain>";

      return s;
   }

   public static String CERT_CHAIN_END() {
      String s = "";

      s += "</CertificateChain></CertificateChains></Data>";

      return s;
   }

   public static String build_digest_content(String wrmheader, String nonce, String keydata, String cipherdata) {
      String xml_req = "";

      xml_req += LA_HEADER_START();
      xml_req += CONTENT_HEADER(wrmheader);
      xml_req += CLIENT_INFO();
      xml_req += LICENSE_NONCE(nonce);
      xml_req += ENCRYPTED_DATA_START();
      xml_req += KEY_INFO(keydata);
      xml_req += CIPHER_DATA(cipherdata);
      xml_req += ENCRYPTED_DATA_END();
      xml_req += LA_HEADER_END();

      return xml_req;
   }

   public static String build_signed_content(String digest) {
      String xml_req = "";

      return xml_req;
   }

   public static String build_signature(Device dev, String data) throws Throwable {
      BCert.Certificate cert = dev.get_cert();
      byte prvkey_sign[] = cert.get_prvkey_for_signing();
      BigInteger prv_sign_key = ECC.make_bi(prvkey_sign, 0, 0x20);
      byte signature_bytes[] = Crypto.ecdsa(data.getBytes(), prv_sign_key);
      String signature = Crypto.base64_encode(signature_bytes);
      System.out.println("XML SIGNATURE");
      System.out.println(signature);
      byte pubkey_sign[] = cert.get_pubkey_for_signing();
      String pubkey = Crypto.base64_encode(pubkey_sign);
      System.out.println("PUBKEY");
      System.out.println(pubkey);
      String xml_req = "";
      xml_req += SIGNATURE(signature);
      xml_req += PUBLIC_KEY(pubkey);
      xml_req += SIGNATURE_END();
      return xml_req;
   }

   public static String build_license_request(Device dev, String wrmheader, String nonce, String keydata, String cipherdata) throws Throwable {
      String xml_req = "";

      xml_req += XML_HEADER_START();
      xml_req += SOAP_BODY_START();
      xml_req += ACQUIRE_LICENSE_HEADER_START();

      String digest_content = build_digest_content(wrmheader, nonce, keydata, cipherdata);
      xml_req += digest_content;

      byte digest_bytes[] = Crypto.SHA256(digest_content.getBytes());
      String digest = Crypto.base64_encode(digest_bytes);

      System.out.println("XML DIGEST");
      System.out.println(digest);

      xml_req += SIGNATURE_START();

      String signed_info = SIGNED_INFO(digest);
      xml_req += signed_info;

      if (fixed_identity()) {
         //random k for ECC signing (XML signature generation)
         BigInteger r = ECC.make_bi(Utils.reverse_hex_string("2238f95e2961b5eea60a64925b14d7fa42d4ba11eb99d7cb956aa056838b6d38"));
         ECC.set_random(r);
      }

      String signature = build_signature(dev, signed_info);

      xml_req += signature;

      xml_req += ACQUIRE_LICENSE_HEADER_END();
      xml_req += SOAP_BODY_END();
      xml_req += XML_HEADER_END();

      return xml_req;
   }

   static byte[] pad16(String s) {
      int len = (s.length() + 0x0f) & 0xfffffff0;

      byte data[] = new byte[len];
      System.arraycopy(s.getBytes(), 0, data, 0, s.length());

      int pad = s.length() % 0x10;

      if (pad != 0) {
         int cnt = 0x10 - pad;

         for (int i = 0; i < cnt; i++) {
            data[s.length() + i] = (byte) cnt;
         }
      }

      return data;
   }

   public static String wrmhdr_from_prothdr(String phdr) throws Throwable {
      byte data[] = Crypto.base64_decode(phdr);

      ByteInput bi = new ByteInput(data);
      bi.little_endian();
      bi.skip(8);

      short size = bi.read_2();

      if (data.length != (size + 10)) ERR.log("Unexpected PROTECTIONHEADER");

      int cnt = size / 2;

      byte wrmhdr[] = new byte[cnt];

      for (int i = 0; i < cnt; i++) {
         short ch = bi.read_2();

         wrmhdr[i] = (byte) ch;
      }

      return new String(wrmhdr);
   }

   public static String get_nonce() throws Throwable {
      byte data[] = ECC.bi_bytes(ECC.random());

      byte nonce[] = new byte[NONCE_SIZE];
      System.arraycopy(data, 0, nonce, 0, NONCE_SIZE);

      Utils.print_buf(0, "nonce", nonce);

      return Crypto.base64_encode(nonce);
   }

   public static String get_cipherdata(Device dev, XmlKey xmlkey) throws Throwable {
      BCert.CertificateChain dchain = dev.get_cert_chain();
      byte chain_data[] = dchain.body();

      String b64_certchain = Crypto.base64_encode(chain_data);

      String s = "";

      s += CERT_CHAIN_START();
      s += " ";
      s += b64_certchain;
      s += " ";
      s += CERT_CHAIN_END();

      byte cert_data[] = pad16(s);

      byte enc_cert_data[] = Crypto.aes_cbc_encrypt(cert_data, xmlkey.aes_iv(), xmlkey.aes_key());

      int iv_len = xmlkey.aes_iv().length;
      int enc_data_len = enc_cert_data.length;

      byte ciphertext[] = new byte[iv_len + enc_data_len];

      System.arraycopy(xmlkey.aes_iv(), 0, ciphertext, 0, iv_len);
      System.arraycopy(enc_cert_data, 0, ciphertext, iv_len, enc_data_len);

      return Crypto.base64_encode(ciphertext);
   }

   public static String get_keydata(Device dev, XmlKey xmlkey) throws Throwable {
      byte keydata[] = xmlkey.bytes();

      byte encrypted[] = Crypto.ecc_encrypt(keydata, getWMRMpubkey());

      return Crypto.base64_encode(encrypted);
   }

   public static String get_license_request(Device dev, String wrmheader) throws Throwable {
      XmlKey xkey = new MSPR.XmlKey();
      if (fixed_identity()) {
         xkey.set_aes_iv(Utils.parse_hex_string("4869b8f5a3dc1cee30ea2c045dde6ec5"));
         xkey.set_aes_key(Utils.parse_hex_string("577c79adfd93be07c3d909e92787ed8a"));
      }
      xkey.print();
      if (fixed_identity()) {
         //random for nonce
         BigInteger r = ECC.make_bi("6d51282ad8c51aa7cc342f031c894534");
         ECC.set_random(r);
      }
      String nonce = get_nonce();
      System.out.println("NONCE");
      System.out.println(nonce);
      if (fixed_identity()) {
         //random k for ECC encryption
         BigInteger r = ECC.make_bi(Utils.reverse_hex_string("bf2aea21c2547e71342a09ead1cc27971342424e32e88c3140942cb11b5b0cfd"));
         ECC.set_random(r);
      }
      String keydata = get_keydata(dev, xkey);
      System.out.println("KEYDATA");
      System.out.println(keydata);
      if (fixed_identity()) {
         //random k for ECC signing (BCert generation)
         BigInteger r = ECC.make_bi(Utils.reverse_hex_string("062dd035241da79eedbc2abc9d99ab5b159788bb78d56aedcc3b603018ec02f7"));
         ECC.set_random(r);
      }
      String cipherdata = get_cipherdata(dev, xkey);
      System.out.println("CIPHERDATA");
      System.out.println(cipherdata);
      String xml_req = build_license_request(dev, wrmheader, nonce, keydata, cipherdata);
      return xml_req;
   }

   public static ECC.ECPoint getWMRMpubkey() {
      return WMRMpubkey;
   }

   public static boolean verify_group_cert_keys() {
      ECC.ECKey k = ECC.ECKey.from_file(BCert.BASE_DIR + File.separatorChar + GROUP_CERT_PRV_KEY);

      BCert bc = BCert.from_file(GROUP_CERT);

      if (k == null) ERR.log("Cannot find private group cert key file: " + GROUP_CERT_PRV_KEY);
      if (bc == null) ERR.log("Cannot find group cert file: " + GROUP_CERT);

      BCert.CertificateChain chain = (BCert.CertificateChain) bc;

      BCert.Certificate cert = chain.get(0);

      if (cert != null) {
         byte pubdata[] = cert.get_pubkey_for_signing();

         ECC.ECPoint pubkey_from_cert = new ECC.ECPoint(pubdata);
         ECC.ECPoint pubkey_from_prvkey = k.pub();

         if (pubkey_from_cert.equals(pubkey_from_prvkey)) return true;
      }

      return false;
   }

   static int align_x10(int size) {
      return ((size + 0x0f) & 0xfffffff0);
   }

   public static byte[] aes_ctr_decrypt(byte data[], int off, int size, byte iv[], byte content_key[]) throws Throwable {
      int asize = align_x10(size);

      byte ciphertext[] = new byte[asize];
      System.arraycopy(data, off, ciphertext, 0, size);

      byte decrypted[] = Crypto.aes_ctr_decrypt(ciphertext, iv, content_key);

      byte plaintext[] = new byte[size];
      System.arraycopy(decrypted, 0, plaintext, 0, size);

      return plaintext;
   }
}
