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
import java.util.*;
import java.io.*;
import org.w3c.dom.*;
import javax.xml.parsers.*;

public class License {
 byte data[];
 Document root;

 byte license_data[];
 byte custom_data[];

 Document custom_root;

 //custom data
 String UserToken;
 String BrandGuid;
 String ClientId;
 String LicenseType;
 String BeginDate;
 String ExpirationDate;
 String ErrorCode;
 String TransactionId;

 BLicense blicense;

 byte content_key[];

 void parse_customdata() {
  if (custom_data!=null) {
   custom_root=XmlUtils.parse_xml(new ByteArrayInputStream(custom_data));

   Node licresp_cdata_node=XmlUtils.select_first(custom_root,"LicenseResponseCustomData");

   if (licresp_cdata_node!=null) {
    String node_val=XmlUtils.get_value(custom_root,"UserToken");

    if (node_val!=null) {
     UserToken=node_val;
    }

    node_val=XmlUtils.get_value(custom_root,"BrandGuid");

    if (node_val!=null) {
     BrandGuid=node_val;
    }

    node_val=XmlUtils.get_value(custom_root,"ClientId");

    if (node_val!=null) {
     ClientId=node_val;
    }

    node_val=XmlUtils.get_value(custom_root,"LicenseType");

    if (node_val!=null) {
     LicenseType=node_val;
    }

    node_val=XmlUtils.get_value(custom_root,"BeginDate");

    if (node_val!=null) {
     BeginDate=node_val;
    }

    node_val=XmlUtils.get_value(custom_root,"ExpirationDate");

    if (node_val!=null) {
     ExpirationDate=node_val;
    }

    node_val=XmlUtils.get_value(custom_root,"ErrorCode");

    if (node_val!=null) {
     ErrorCode=node_val;
    }

    node_val=XmlUtils.get_value(custom_root,"TransactionId");

    if (node_val!=null) {
     TransactionId=node_val;
    }
   }
  }
 }

 void parse_license() {
  blicense=new BLicense(license_data);
 }

 public License(byte xml[]) {
  this.data=data;

  root=XmlUtils.parse_xml(new ByteArrayInputStream(xml));
   
  Node licresp_node=XmlUtils.select_first(root,"soap:Envelope.soap:Body.AcquireLicenseResponse.AcquireLicenseResult.Response.LicenseResponse");

  if (licresp_node!=null) {
   String license=XmlUtils.get_value(licresp_node,"Licenses.License");
   String custom=XmlUtils.get_value(licresp_node,"CustomData");

   try {
    license_data=Crypto.base64_decode(license);
    custom_data=Crypto.base64_decode(custom);

    parse_customdata();
    parse_license();
   } catch(Throwable t) {
    t.printStackTrace();
   }
  }
 }

 public byte[] get_key_id() {
  BLicense.ContentKey ck=(BLicense.ContentKey)blicense.get_attr("OuterContainer.KeyMaterialContainer.ContentKey");

  if (ck!=null) {
   return ck.key_id();
  }

  return null;  
 }

 public byte[] get_encrypted_data() {
  BLicense.ContentKey ck=(BLicense.ContentKey)blicense.get_attr("OuterContainer.KeyMaterialContainer.ContentKey");

  if (ck!=null) {
   return ck.enc_data();
  }

  return null;  
 }

 public byte[] get_content_key() {
  if (content_key==null) {
   byte encrypted_data[]=get_encrypted_data();

   Device cur_dev=Device.cur_device();
   byte plaintext[]=Crypto.ecc_decrypt(encrypted_data,cur_dev.enc_key().prv());

   content_key=new byte[0x10];

   System.arraycopy(plaintext,0x10,content_key,0,0x10);
  }

  return content_key;
 }

 public void print() {
  PaddedPrinter pp=Shell.get_pp();

  pp.println("LICENSE");

  pp.pad(2,"");

  pp.println("CUSTOM DATA");
  pp.pad(2,"");

  pp.println("UserToken:       "+UserToken);
  pp.println("BrandGuid:       "+BrandGuid);
  pp.println("LicenseType:     "+LicenseType);
  pp.println("BeginDate:       "+BeginDate);
  pp.println("ExpirationDate:  "+ExpirationDate);
  pp.println("ErrorCode:       "+ErrorCode);
  pp.println("TransactionId:   "+TransactionId);
  pp.leave();

  blicense.print();

  pp.printhex("content_key",get_content_key());

  pp.leave();
 }
}
