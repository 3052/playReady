/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package agsecres.helper;

import agsecres.tool.*;
import java.lang.*;
import java.lang.reflect.*;
import java.net.*;
import java.io.*;
import java.util.*;
import java.math.*;
import java.security.*;
import java.security.cert.*;
import javax.net.ssl.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import sun.net.www.*;

public class Web {
   public static class CleanMessageHeader extends MessageHeader {
      //ignore setting unneeded properties
      public void setIfNotSet(String k, String v) {}
   }

   public static CleanMessageHeader raw_headers(HttpURLConnection conn) throws Throwable {
      if (conn instanceof HttpsURLConnection) {
         //get delegate to HttpURLConnection
         Class c = Class.forName("sun.net.www.protocol.https.HttpsURLConnectionImpl");

         Field f = c.getDeclaredField("delegate");
         f.setAccessible(true);

         conn = (HttpURLConnection) f.get(conn);
      }

      Class c = Class.forName("sun.net.www.protocol.http.HttpURLConnection");

      Field f = c.getDeclaredField("requests");
      f.setAccessible(true);

      CleanMessageHeader hdrs = new CleanMessageHeader();
      f.set(conn, hdrs);

      return hdrs;
   }

   public static final String USER_AGENT = "Mozilla/5.0 (ADB)";

   public static final String BASE_DIR = "secrets";

   public static String KSFILE = Vars.get_str("KSFILE");
   public static String KSPASSFILE = Vars.get_str("KSPASSFILE");

   public static final int BUFSIZE = 0x100000;

   public static final int TIMEOUT_VAL = 2000;

   public static class MyTrustManager implements X509TrustManager {
      public X509Certificate[] getAcceptedIssuers() {
         return null;
      }
      public void checkClientTrusted(X509Certificate[] certs, String authType) {}
      public void checkServerTrusted(X509Certificate[] certs, String authType) {}
   }

   public static class PathInfo {
      String url;
      String actual_url;
      int resp_code;
      Hashtable < String, String > hdrs;

      public PathInfo(String url, String actual_url, int resp_code, Hashtable < String, String > hdrs) {
         this.url = url;
         this.actual_url = actual_url;
         this.resp_code = resp_code;
         this.hdrs = hdrs;
      }

      public static Hashtable < String, String > get_hdrs(HttpURLConnection conn) {
         Hashtable hdrs = new Hashtable < String, String > ();

         int idx = 1;
         while (true) {
            String key = conn.getHeaderFieldKey(idx);
            String val = conn.getHeaderField(idx);

            if ((key == null) || (val == null)) break;

            hdrs.put(key, val);

            idx++;
         }

         return hdrs;
      }

      public static PathInfo for_url(String s_url, String reqprops[]) {
         try {
            URL url = new URL(s_url);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            //    conn.setFollowRedirects(false);

            conn.setRequestMethod("HEAD");

            CleanMessageHeader req_hdrs = set_headers(conn, reqprops);
            req_hdrs.add("TimeSeekRange.dlna.org", "npt=0-");

            //   conn.setRequestProperty("Connection","close");
            conn.connect();

            int resp_code = conn.getResponseCode();

            Hashtable < String, String > resp_hdrs = get_hdrs(conn);

            return new PathInfo(s_url, conn.getURL().toString(), resp_code, resp_hdrs);
         } catch (Throwable t) {}

         return null;
      }

      public String url() {
         return url;
      }

      public String actual_url() {
         return actual_url;
      }

      public String get_hdr(String key) {
         return hdrs.get(key);
      }

      public void print() {
         PaddedPrinter pp = Shell.get_pp();

         pp.println("PATH INFO");
         pp.println("url:        " + url);
         pp.println("actual url: " + actual_url);
         pp.pad(2, "");

         Enumeration < String > keys = hdrs.keys();

         while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            String val = hdrs.get(key);

            pp.println(Utils.padded_string(key, 16) + ": " + val);
         }

         pp.leave();
      }
   }

   static SSLContext createSSLContext(String ksfile, String kspassfile) {
      SSLContext sslcontext = null;
      try {
         KeyStore keystore = KeyStore.getInstance("JKS");

         String kspath = BASE_DIR + File.separatorChar + ksfile;
         String kspasspath = BASE_DIR + File.separatorChar + kspassfile;

         byte data[] = Utils.load_file(kspasspath);
         if (data == null) return null;

         String kspass = new String(data);

         FileInputStream fileinputstream = new FileInputStream(kspath);
         keystore.load(fileinputstream, kspass.toCharArray());
         fileinputstream.close();

         KeyManagerFactory keymanagerfactory = KeyManagerFactory.getInstance("SunX509");
         keymanagerfactory.init(keystore, kspass.toCharArray());

         KeyManager akeymanager[] = keymanagerfactory.getKeyManagers();

         TrustManagerFactory trustmanagerfactory = TrustManagerFactory.getInstance("SunX509");
         trustmanagerfactory.init((KeyStore) null);

         sslcontext = SSLContext.getInstance("TLS");

         TrustManager[] tmtab = new TrustManager[1];
         tmtab[0] = new MyTrustManager();

         sslcontext.init(akeymanager, tmtab, new SecureRandom());
      } catch (Throwable t) {
         t.printStackTrace();
      }

      return sslcontext;
   }

   static void init_https() {
      try {
         SSLContext sslcontext = createSSLContext(KSFILE, KSPASSFILE);

         if (sslcontext != null)
            HttpsURLConnection.setDefaultSSLSocketFactory(sslcontext.getSocketFactory());
      } catch (Exception e) {
         System.out.println("Cannot initialize SSL context");
         System.exit(1);
      }
   }

   static {
      init_https();
      System.setProperty("sun.net.http.allowRestrictedHeaders", "true");
   }

   public static void sleep(int time) {
      try {
         Thread.currentThread().sleep(time);
      } catch (Throwable t) {}
   }

   public static CleanMessageHeader set_headers(HttpURLConnection conn, String reqprops[]) throws Throwable {
      CleanMessageHeader hdrs = raw_headers(conn);

      for (int i = 0; i < reqprops.length; i += 2) {
         String prop = reqprops[i];
         String value = reqprops[i + 1];

         //conn.setRequestProperty(prop,value);
         hdrs.add(prop, value);
      }

      hdrs.add("User-Agent", USER_AGENT);

      return hdrs;
   }

   public static byte[] https_get(String urlstr, String reqprops[]) {
      boolean successfull = false;
      byte res_data[] = null;

      while (!successfull) {
         try {
            res_data = https_get_internal(urlstr, reqprops);
            if (res_data != null) successfull = true;
         } catch (Throwable t) {}
      }

      return res_data;
   }

   public static byte[] https_get_internal(String urlstr, String reqprops[]) {
      //String result="";
      byte res_data[] = null;

      try {
         // Thread.currentThread().sleep(100);
      } catch (Throwable t) {}

      //System.out.println("https_get: "+urlstr);

      try {
         URL url = new URL(urlstr);
         HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
         conn.setConnectTimeout(TIMEOUT_VAL);
         conn.setRequestMethod("GET");

         CleanMessageHeader hdrs = set_headers(conn, reqprops);
         hdrs.add("Connection", "close");
         conn.connect();

         BufferedInputStream bis = new BufferedInputStream(conn.getInputStream());
         ByteArrayOutputStream baos = new ByteArrayOutputStream();

         try {
            byte[] buffer = new byte[BUFSIZE];
            int size;

            while ((size = bis.read(buffer)) != -1) {
               //     System.out.println("read: "+size);
               baos.write(buffer, 0, size);
            }

            res_data = baos.toByteArray();
         } finally {
            baos.close();
            bis.close();
            //conn.disconnect();
         }
      } catch (Throwable e) {
         //   e.printStackTrace();
         //   System.out.println("timeout!");
         sleep(1000);
         res_data = null;
      }

      //System.out.println("https_get res: "+new String(res_data));

      return res_data;
   }

   public static String https_post(String s_url, String msg, String reqprops[]) {
      boolean successfull = false;
      String result = "";

      while (!successfull) {
         try {
            result = https_post_internal(s_url, msg, reqprops);
            if (result.length() > 0) successfull = true;
         } catch (Throwable t) {}
      }

      return result;
   }

   public static String https_post_internal(String s_url, String msg, String reqprops[]) {
      String result = "";

      try {
         URL url = new URL(s_url);
         HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
         conn.setConnectTimeout(TIMEOUT_VAL);

         conn.setRequestMethod("POST");
         conn.setRequestProperty("Content-Length", "" + msg.length());
         conn.setRequestProperty("User-Agent", USER_AGENT);
         conn.setRequestProperty("Accept-language", "en, *");

         for (int i = 0; i < reqprops.length; i += 2) {
            String prop = reqprops[i];
            String value = reqprops[i + 1];

            conn.setRequestProperty(prop, value);
         }

         conn.setRequestProperty("Connection", "close");

         conn.setDoInput(true);
         conn.setDoOutput(true);

         PrintWriter out = new PrintWriter(new OutputStreamWriter(conn.getOutputStream()));
         out.print(msg);

         out.close();

         conn.connect();

         InputStream in = null;

         int code = conn.getResponseCode();

         if (code == 200) in = conn.getInputStream();
         else in = conn.getErrorStream();

         if (in == null) {
            Shell.println("HTTP error code " + code);
         }

         int idx = 1;
         while (true) {
            String key = conn.getHeaderFieldKey(idx);
            String val = conn.getHeaderField(idx);

            if ((key == null) || (val == null)) break;

            //    System.out.println(key+": "+val);

            idx++;
         }

         BufferedReader b = new BufferedReader(new InputStreamReader(in, "utf-8"));
         String line = b.readLine();

         while (line != null) {
            result = result + line;
            line = b.readLine();
         }

         b.close();
         in.close();
      } catch (Throwable e) {
         //e.printStackTrace();
         //   System.out.println("timeout!");
         sleep(1000);
         result = "";
      }

      return result;
   }

   public static long http_get_to_file(String s_url, String reqprops[], String outfile) {
      long size = -1;

      try {
         FileOutputStream fos = new FileOutputStream(outfile);

         size = http_get(s_url, reqprops, fos);
      } catch (Throwable t) {
         t.printStackTrace();
      }

      return size;
   }

   public static byte[] http_get_to_array(String s_url, String reqprops[]) {
      ByteArrayOutputStream baos = new ByteArrayOutputStream();

      long size = http_get(s_url, reqprops, baos);

      if (size >= 0) {
         return baos.toByteArray();
      }

      return null;
   }

   public static long http_get(String urlstr, String reqprops[], OutputStream os) {
      boolean successfull = false;
      long cnt = -1;

      while (!successfull) {
         try {
            cnt = http_get_internal(urlstr, reqprops, os);
            if (cnt > 0) successfull = true;
         } catch (Throwable t) {}
      }

      return cnt;
   }

   public static long http_get_internal(String s_url, String reqprops[], OutputStream os) {
      long cnt = 0;

      try {
         //   System.out.println("GET for: "+s_url);

         URL url = new URL(s_url);
         HttpURLConnection conn = (HttpURLConnection) url.openConnection();
         conn.setConnectTimeout(TIMEOUT_VAL);
         conn.setFollowRedirects(true);

         conn.setRequestMethod("GET");
         set_headers(conn, reqprops);
         conn.connect();

         int code = conn.getResponseCode();

         //   System.out.println("HTTP RESP: "+code);

         BufferedInputStream bis = new BufferedInputStream(conn.getInputStream());

         try {
            byte[] buffer = new byte[BUFSIZE];
            int size;

            while ((size = bis.read(buffer)) != -1) {
               //     System.out.println("read: "+size);
               os.write(buffer, 0, size);
               cnt += size;
            }
         } finally {
            os.close();
            bis.close();
         }
      } catch (Throwable t) {
         //   System.out.println("timeout!");
         sleep(1000);
         cnt = -1;
      }

      return cnt;
   }

   public static long http_head(String s_url, String reqprops[], String outfile) {
      long cnt = 0;

      try {
         //   System.out.println("HEAD for: "+s_url);

         URL url = new URL(s_url);
         HttpURLConnection conn = (HttpURLConnection) url.openConnection();
         //   conn.setFollowRedirects(false);

         conn.setRequestMethod("HEAD");

         CleanMessageHeader hdrs = set_headers(conn, reqprops);
         hdrs.add("TimeSeekRange.dlna.org", "npt=0-");

         //conn.setRequestProperty("Connection","close");

         conn.connect();

         int code = conn.getResponseCode();

         //   System.out.println("HTTP RESP: "+code);

         //   System.out.println("REAL URL: "+conn.getURL());

         //   System.out.println("[HEADERS]");

         int idx = 1;
         while (true) {
            String key = conn.getHeaderFieldKey(idx);
            String val = conn.getHeaderField(idx);

            if ((key == null) || (val == null)) break;

            //    System.out.println(key+": "+val);

            idx++;
         }

         BufferedInputStream bis = new BufferedInputStream(conn.getInputStream());
         FileOutputStream fos = new FileOutputStream(outfile);

         try {
            byte[] buffer = new byte[BUFSIZE];
            int size;

            while ((size = bis.read(buffer)) != -1) {
               //     System.out.println("read: "+size);
               fos.write(buffer, 0, size);
               cnt += size;
            }
         } finally {
            fos.close();
            bis.close();
         }
      } catch (Throwable t) {
         t.printStackTrace();

         cnt = -1;
      }

      return cnt;
   }
}
