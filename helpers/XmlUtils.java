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
import java.util.*;
import java.io.*;
import org.w3c.dom.*;
import javax.xml.parsers.*;

public class XmlUtils {
   public static String[] tokenize_path(String path) {
      return Utils.tokenize(path, ".");
   }

   //public static Document open_xml(String path) {
   //   Document doc = null;

   //   try {
   //      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
   //      DocumentBuilder db = dbf.newDocumentBuilder();
   //      doc = db.parse(new File(path));
   //      doc.getDocumentElement().normalize();
   //   } catch (Throwable t) {
   //      t.printStackTrace();
   //   }

   //   return doc;
   //}

   public static Document parse_xml(InputStream is) {
      Document doc = null;

      try {
         DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
         DocumentBuilder db = dbf.newDocumentBuilder();
         doc = db.parse(is);
         doc.getDocumentElement().normalize();
      } catch (Throwable t) {
         t.printStackTrace();
      }

      return doc;
   }

   public static Node[] get_elements(Object from, String tag) {
      NodeList list = null;
      Node table[] = null;

      if (from instanceof Document) {
         list = ((Document) from).getElementsByTagName(tag);

         table = new Node[list.getLength()];

         for (int i = 0; i < table.length; i++) {
            table[i] = list.item(i);
         }
      } else

      if (from instanceof Node) {
         list = ((Node) from).getChildNodes();

         Vector < Node > matched = new Vector < Node > ();

         for (int i = 0; i < list.getLength(); i++) {
            Node node = list.item(i);

            String name = node.getNodeName();

            if (name.equals(tag)) matched.addElement(node);
         }

         table = matched.toArray(new Node[0]);
      }

      return table;
   }

   public static Node first_element(Node start, String tag) {
      Node tmp[] = get_elements(start, tag);

      if (tmp.length > 0) return tmp[0];

      return null;
   }

   public static String get_attr_value(Node node, String attr) {
      if (node instanceof Element) {
         String attval = ((Element) node).getAttribute(attr);

         return attval;
      }

      return null;
   }

   public static Node[] select(Node from, String path) {
      String tags[] = tokenize_path(path);

      for (int i = 0; i < tags.length - 1; i++) {
         from = first_element(from, tags[i]);
      }

      return get_elements(from, tags[tags.length - 1]);
   }

   public static Node select_first(Node from, String path) {
      Node nodes[] = select(from, path);

      if ((nodes != null) && (nodes.length > 0)) return nodes[0];

      return null;
   }

   //public static Node[] select_by_attr_value(Node[] list, String filter) {
   //   String keyval[] = Utils.tokenize(filter, "=");

   //   if (keyval.length != 2) return null;

   //   String attr = keyval[0];
   //   String val = keyval[1];

   //   Vector < Node > matched = new Vector < Node > ();

   //   for (int i = 0; i < list.length; i++) {
   //      Node node = list[i];

   //      if (node instanceof Element) {
   //         String attval = ((Element) node).getAttribute(attr);

   //         if (attval.equals(val)) {
   //            matched.addElement(node);
   //         }
   //      }
   //   }

   //   return matched.toArray(new Node[0]);
   //}

   //public static String get_filtered_attr(Node from, String path, String filter, String attr) {
   //   Node[] list = select(from, path);

   //   if (list.length > 0) {
   //      Node filtered_nodes[] = select_by_attr_value(list, filter);

   //      if (filtered_nodes.length > 0) {
   //         return get_attr_value(filtered_nodes[0], attr);
   //      }
   //   }

   //   return null;
   //}

   //public static String get_attr(Node from, String path, String attr) {
   //   Node[] list = select(from, path);

   //   if (list.length > 0) {
   //      return get_attr_value(list[0], attr);
   //   }

   //   return null;
   //}

   public static String get_value(Node node) {
      return node.getTextContent();
   }

   public static String get_value(Node from, String path) {
      Node[] list = select(from, path);

      if (list.length > 0) {
         return get_value(list[0]);
      }

      return null;
   }

   public static void fill_instance(Object instance, Class clazz, Node node) {
      try {
         Field ftab[] = clazz.getDeclaredFields();

         for (int i = 0; i < ftab.length; i++) {
            Field f = ftab[i];

            String fname = f.getName();

            if (fname.startsWith("att")) {
               fname = fname.substring(3);

               String value = XmlUtils.get_attr_value(node, fname);

               if (value != null) {
                  f.setAccessible(true);
                  f.set(instance, value);
               }
            }
         }
      } catch (Throwable t) {
         t.printStackTrace();
      }
   }

   public static Object instance_from_node(Class<?> clazz, Node node) {
      Object instance = null;

      try {
         instance = clazz.getConstructor().newInstance();
         
         while (clazz != null) {
            fill_instance(instance, clazz, node);

            clazz = clazz.getSuperclass();
         }
      } catch (Throwable t) {
         instance = null;
         t.printStackTrace();
      }

      return instance;
   }

}
