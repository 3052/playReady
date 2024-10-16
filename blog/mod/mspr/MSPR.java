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

 public static String ACQUIRE_LICENSE_HEADER_END() {
  String s="";

  s+="</Challenge></challenge></AcquireLicense>";
 
  return s;
 }

 public static String SOAP_BODY_END() {
  String s="";

  s+="</soap:Body>";

  return s;
 }

 public static String XML_HEADER_END() {
  String s="";

  s+="</soap:Envelope>";

  return s;
 }

 public static String build_license_request(Device dev,String wrmheader,String nonce,String keydata,String cipherdata) throws Throwable {
  String xml_req="";

  xml_req+=XML_HEADER_START();
  xml_req+=SOAP_BODY_START();
  xml_req+=ACQUIRE_LICENSE_HEADER_START();

  String digest_content=build_digest_content(wrmheader,nonce,keydata,cipherdata);
  xml_req+=digest_content;

  byte digest_bytes[]=Crypto.SHA256(digest_content.getBytes());
  String digest=Crypto.base64_encode(digest_bytes);

  xml_req+=SIGNATURE_START();  

  String signed_info=SIGNED_INFO(digest);
  xml_req+=signed_info;

  if (fixed_identity()) {
   //random k for ECC signing (XML signature generation)
   BigInteger r=ECC.make_bi(Utils.reverse_hex_string("2238f95e2961b5eea60a64925b14d7fa42d4ba11eb99d7cb956aa056838b6d38"));
   ECC.set_random(r);
  }

  String signature=build_signature(dev,signed_info);

  xml_req+=signature;

  xml_req+=ACQUIRE_LICENSE_HEADER_END();
  xml_req+=SOAP_BODY_END();
  xml_req+=XML_HEADER_END();

  return xml_req;
 }

}
