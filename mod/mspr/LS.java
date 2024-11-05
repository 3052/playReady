/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package mod.mspr;

import agsecres.helper.*;
import mod.cdn.*;
import java.lang.*;
import java.util.*;

public class LS {
   public static String[] get_reqprops(Device dev) {
      return new String[] {
         "Content-type",
         "text/xml; charset=utf-8",
         "Mac",
         dev.get_mac(),
         "Soapaction",
         "http://schemas.microsoft.com/DRM/2007/03/protocols/AcquireLicense"
      };
   }

   public static String send_license_req(String ls_url, Device dev, String msg) {
      return Web.https_post(ls_url, msg, get_reqprops(dev));
   }
}
