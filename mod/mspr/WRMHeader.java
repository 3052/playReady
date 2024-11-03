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
import java.lang.reflect.*;
import java.util.*;
import java.io.*;
import org.w3c.dom.*;
import javax.xml.parsers.*;

public class WRMHeader {
 byte data[];
 Document root;

 String keylen;
 String algid;
 byte kid[];
 String la_url;
 byte ds_id[];

 public String keylen() {
  return keylen;
 }

 public String algid() {
  return algid;
 }

 public byte[] kid() {
  return kid;
 }

 public String la_url() {
  return la_url;
 }

 public byte[] ds_id() {
  return ds_id;
 }

 public WRMHeader(byte data[]) throws Throwable {
  this.data=data;

  root=XmlUtils.parse_xml(new ByteArrayInputStream(data));

  String node_val=XmlUtils.get_value(root,"WRMHEADER.DATA.PROTECTINFO.KEYLEN");
  if (node_val!=null) {
   keylen=node_val;
  }

  node_val=XmlUtils.get_value(root,"WRMHEADER.DATA.PROTECTINFO.ALGID");
  if (node_val!=null) {
   algid=node_val;
  }

  node_val=XmlUtils.get_value(root,"WRMHEADER.DATA.KID");
  if (node_val!=null) {
   kid=Crypto.base64_decode(node_val);
  }

  node_val=XmlUtils.get_value(root,"WRMHEADER.DATA.LA_URL");
  if (node_val!=null) {
   la_url=node_val;
  }

  node_val=XmlUtils.get_value(root,"WRMHEADER.DATA.DS_ID");
  if (node_val!=null) {
   ds_id=Crypto.base64_decode(node_val);
  }
 }

 public void print() {
  PaddedPrinter pp=Shell.get_pp();

  pp.println("WRMHEADER");
  pp.pad(2,"");

  pp.println("keylen: "+keylen);
  pp.println("algid:  "+algid);
  pp.printhex("kid",kid);
  pp.println("la_url: "+la_url);
  pp.printhex("ds_id: ",ds_id);

  pp.leave();
 }
}
