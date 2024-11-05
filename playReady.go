package main

import (
   "os"
   "os/exec"
)

func main() {
   os.Setenv("PATH", "C:/Program Files/Android/Android Studio/jbr/bin")
   data, err := exec.Command("java", "agsecres.tool.Hello").CombinedOutput()
   if err != nil {
      panic(err)
   }
   err = os.WriteFile("playReady.txt", data, os.ModePerm)
   if err != nil {
      panic(err)
   }
}
