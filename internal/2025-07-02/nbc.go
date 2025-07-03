package main

import (
   "io"
   "net/http"
   "net/url"
   "os"
   "strings"
)

func main() {
   var req http.Request
   req.Header = http.Header{}
   req.Method = "POST"
   req.URL = &url.URL{}
   req.URL.Host = "ss.nbc.co"
   req.URL.Path = "/pontoon/verify"
   req.URL.Scheme = "https"
   req.Body = io.NopCloser(body)
   resp, err := http.DefaultClient.Do(&req)
   if err != nil {
      panic(err)
   }
   err = resp.Write(os.Stdout)
   if err != nil {
      panic(err)
   }
}

var body = strings.NewReader(`
{
   "address":"hello@mailsac.com"
}
`)
