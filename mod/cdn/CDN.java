/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package mod.cdn;

import agsecres.tool.*;
import agsecres.helper.*;
import java.lang.*;
import java.lang.reflect.*;
import java.security.*;
import java.util.*;
import java.math.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.net.*;

public class CDN {
 public static final String secret = Vars.get_str("VOD_SECRET");

 public static boolean no_auth() {
  return Vars.get_int("CDN_NOAUTH")==1;
 }

 public static String get_secret() {
  return secret;
 }

 public static String get_time() {
  long unix_time=System.currentTimeMillis()/1000L;
 
  return ""+unix_time;
 }

 public static String get_nbox_code(String serial,String time) {
  String magic=serial+";"+time+";"+get_secret();

  byte digest[]=Crypto.MD5(magic.getBytes());

  String nbox_code=Utils.construct_hex_string(digest);

  if (no_auth()) {
   //use random value for Nbox code
   byte random[]=ECC.bi_bytes(ECC.random(128));
   nbox_code=Utils.construct_hex_string(random);
  }

  return nbox_code;
 } 

 public static String[] get_reqprops(String serial) {
  String time=get_time();
  
  return new String[]{
   "FriendlyName.dlna.org",   "nBox",
   "Range",                   "bytes=0-",
   "X-nBox-Code",             get_nbox_code(serial,time),
   "X-nBox-SerialNumber",     serial,
   "X-nBox-Time",             time
  };
 }

 public static Web.PathInfo get_pathinfo(String serial,String url) {
  return Web.PathInfo.for_url(url,get_reqprops(serial));
 }

 public static long download_content(String serial,String url,String outfile) {
  return Web.http_get_to_file(url,get_reqprops(serial),outfile);
 }

 public static long check_content(String serial,String url,String outfile) {
  return Web.http_head(url,get_reqprops(serial),outfile);
 }
}
