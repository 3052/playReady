package main

import (
   "bytes"
   "encoding/json"
   "fmt"
   "net/http"
)

type verify struct {
   Response struct {
      Status string
      SubStatus string `json:"sub_status"`
   }
}

func (v *verify) New() error {
   data, err := json.Marshal(map[string]string{
      "address": address,
   })
   if err != nil {
      return err
   }
   resp, err := http.Post(
      "https://ss.nbc.co/pontoon/verify", "", bytes.NewReader(data),
   )
   if err != nil {
      return err
   }
   defer resp.Body.Close()
   return json.NewDecoder(resp.Body).Decode(v)
}

func main() {
   var pontoon verify
   err := pontoon.New()
   if err != nil {
      panic(err)
   }
   fmt.Printf("%+v\n", pontoon)
}

// github.com/disposable-email-domains/disposable-email-domains

//{Response:{Status:valid SubStatus:alternate}}
//const address = "367@tuta.io"

//url: "tempmail.best",
//const address = "darkened.firefighter@linkmail.info"

//const address = "hello@maildrop.cc"

//const address = "hello@mailnesia.com"

//const address = "hello@mailsac.com"

//mail.td
//const address = "yq2t6q1n@nqmo.com"

//mail.tm
//const address = "coralflss@punkproof.com"

//const address = "hello@smail.pw"

//const address = "hello@snapmail.cc"

//mail.gw
//const address = "kngehqqipmv@teihu.com"

//const address = "hello@vmail.dev"

//moakt.com
//const address = "hello@teml.net"

//guerrillamail.com
//const address = "hello@sharklasers.com"

// adguard.com/en/adguard-temp-mail/overview.html)
//early.peacock.wfiy@letterhaven.net

//https://10minutemail.net
//xae99222@jioso.com

//{Response:{Status:do_not_mail SubStatus:mx_forward}}
//https://smailpro.com
//const address = "of00qz4fewhl@dugmail.com"

//https://yopmail.com
//const address = "hello@alphax.fr.nf"

//{Response:{Status:invalid SubStatus:no_dns_entries}}
//nowmymail.com
//const address = "pwdpwgbydm@mymailprotection.xyz"

//dropmail.me/
//urufalbul@emlpro.com

//https://tempmail.plus
//uckuk@mailto.plus

//https://inboxes.com
//asdasdf@spicysoda.com

///

//https://tempmailbox.net

//
//https://10minutemail.com/ 随机生成前后缀，默认每次 10
//分钟，可在过期前不限次数地续时间，2007
//年运营至今的临时邮箱服务；[该作者](https://www.digitalsanctuary.com/)另一个临时邮箱服务为[https://temp-mail.org/
//](https://temp-mail.org/)；
//
//https://linshiyou.com/ （可自定义前缀，有两个后缀可选）和
//[22.do](https://22.do/) （两个服务为同一作者的作品，后者可提供临时 Gmail
//邮箱）；
//
//[https://www.mohmal.com](https://www.mohmal.com/en) 可自定义前后缀的、有效期 45
//分钟的临时域名邮箱；
//
//https://linshiyouxiang.net/ 十秒钟内收到邮件，可自定义前缀、后缀；
//
//https://tempmail.altmails.com/ 临时邮箱，可设置为中转邮箱；
//
//https://mailnesia.com/ 便捷的匿名邮箱，可自定义前缀，后缀为 @Mailnesia.com；
//
//https://www.emailondeck.com/ 随机前缀，付费版可长期使用；
//
//https://www.disposablemail.com/ 有效期最长 2 周；
//
//https://spambox.xyz/ 可自定义前缀，有 4 个后缀可选；
//
//https://mailgolem.com/ 随机生成前缀，后缀为 @mailgolem.com ；
//
//https://mailpoof.com/ 前缀可自定义，后缀为 @mailpoof.com；
//
//https://www.crazymailing.com/ 随机生成前缀的临时邮箱；
//
//https://edumail.icu/ 可生成临时教育邮箱；
//
//https://etempmail.com/ 带 edu.pl 的临时教育邮箱；
//
//https://www.linshi-email.com/ 有效期 10 分钟的临时邮箱；
//
//https://ihotmails.com/ 可自定义前缀，按钮设计有待优化.
//
//igdux.com/tempmail)

