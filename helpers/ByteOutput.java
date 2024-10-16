/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS    */
/* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,*/
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL    */
/* SECURITY EXPLORATIONS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, */
/* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF  */
/* OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE     */
/* SOFTWARE.                                                                  */

package agsecres.helper;

import java.lang.*;
import java.io.*;

public class ByteOutput {
 byte data[];
 int capacity;

 int off;
 int len;

 boolean le;

 private boolean in_range(int pos,int len) {
  if ((pos<capacity)&&((pos+len)<capacity)) return true;
   else return false;
 }

 private void extend_capacity() {
  int newcap=2*capacity;

  byte newdata[]=new byte[newcap];
  System.arraycopy(data,0,newdata,0,capacity);

  this.capacity=newcap;
  this.data=newdata;
 }

 private void check_space(int len) {
  while(!in_range(off,len)) extend_capacity();
 }

 private void set_len(int pos) {
  if (off>len) len=off;
 }

 public ByteOutput(int capacity) {
  this.capacity=capacity;
  this.data=new byte[capacity];
  this.off=0;
  this.len=0;   
 }

 public void write_1(byte val) {
  check_space(1);
   
  data[off++]=val;

  set_len(off);
 }

 public void write_2(short val) {
  check_space(2);

  byte b1=(byte)((val>>8)&0xff);
  byte b2=(byte)((val)&0xff);

  if (le) {
   data[off++]=b2;
   data[off++]=b1;
  } else {
   data[off++]=b1;
   data[off++]=b2;
  }

  set_len(off);
 }

 //weird one
 public void write_3(int val) {
  check_space(3);

  byte b1=(byte)((val>>16)&0xff);
  byte b2=(byte)((val>>8)&0xff);
  byte b3=(byte)((val)&0xff);
 
  if (le) {
   data[off++]=b3;
   data[off++]=b2;
   data[off++]=b1;
  } else {
   data[off++]=b1;
   data[off++]=b2;
   data[off++]=b3;
  }

  set_len(off);
 }

 public void write_4(int val) {
  check_space(4);

  byte b1=(byte)((val>>24)&0xff);
  byte b2=(byte)((val>>16)&0xff);
  byte b3=(byte)((val>>8)&0xff);
  byte b4=(byte)((val)&0xff);
 
  if (le) {
   data[off++]=b4;
   data[off++]=b3;
   data[off++]=b2;
   data[off++]=b1;
  } else {
   data[off++]=b1;
   data[off++]=b2;
   data[off++]=b3;
   data[off++]=b4;
  }

  set_len(off);
 }

 public void write_8(long val) {
  check_space(8);

  byte b1=(byte)((val>>56)&0xff);
  byte b2=(byte)((val>>48)&0xff);
  byte b3=(byte)((val>>40)&0xff);
  byte b4=(byte)((val>>32)&0xff);
  byte b5=(byte)((val>>24)&0xff);
  byte b6=(byte)((val>>16)&0xff);
  byte b7=(byte)((val>>8)&0xff);
  byte b8=(byte)((val)&0xff);
 
  if (le) {
   data[off++]=b8;
   data[off++]=b7;
   data[off++]=b6;
   data[off++]=b5;
   data[off++]=b4;
   data[off++]=b3;
   data[off++]=b2;
   data[off++]=b1;
  } else {
   data[off++]=b1;
   data[off++]=b2;
   data[off++]=b3;
   data[off++]=b4;
   data[off++]=b5;
   data[off++]=b6;
   data[off++]=b7;
   data[off++]=b8;
  }

  set_len(off);
 }

 public void write_n(byte bytes[]) {
  int n=bytes.length;

  check_space(n);

  System.arraycopy(bytes,0,data,off,n);
  off+=n;

  set_len(off);
 }

 public void write_string(String s) {
  write_n(s.getBytes());
  write_1((byte)0);
 }

 public void write_zero(int cnt) {
  for(int i=0;i<cnt;i++) {
   write_1((byte)0);
  }
 }

 public int set_pos(int new_off) {
  int old_off=off;
  off=new_off;
 
  return old_off;
 }

 public int get_pos() {
  return off;
 }

 public int length() {
  return len;
 }

 public void skip(int cnt) {
  off+=cnt;
 }

 public void little_endian() {
  le=true;
 }

 public void big_endian() {
  le=false;
 }

 public byte[] bytes() {
  byte res[]=new byte[len];
  System.arraycopy(data,0,res,0,len);

  return res;
 }
}
