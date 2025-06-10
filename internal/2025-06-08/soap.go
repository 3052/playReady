package soap

type module struct {
   url    string
   go_sum int
}

var modules = []module{
   {
      url:    "github.com/achiku/soapc/issues/3",
      go_sum: 8,
   },
   {
      url:    "github.com/droyo/go-xml",
      go_sum: 25,
   },
   {
      url:    "github.com/foomo/soap/issues/9",
      go_sum: 0,
   },
   {
      url:    "github.com/juju/xml/issues/7",
      go_sum: 0,
   },
   {
      url:    "github.com/radoslav/soap/issues/1",
      go_sum: 0,
   },
   {
      url:    "github.com/textnow/gosoap/issues/5",
      go_sum: 12,
   },
   {
      url:    "github.com/tiaguinho/gosoap",
      go_sum: 16,
   },
}
