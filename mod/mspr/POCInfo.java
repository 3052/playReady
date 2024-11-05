/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package mod.mspr;

import java.lang.*;

public class POCInfo {
   public static final String UUID = "(c)";
   public static final String MSG = "Proof of Concept MP4 file demonstrating weak content protection in the environment of CANAL+ (Microsoft PlayReady DRM case)";

   public static void replace_array_content(byte array[], String str) {
      int alen = array.length;

      byte data[] = str.getBytes();

      int slen = data.length;

      if (slen > alen) slen = alen;

      for (int i = 0; i < slen; i++) {
         array[i] = data[i];
      }

      for (int i = slen; i < alen; i++) {
         array[i] = 0;
      }
   }
}
