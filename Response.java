package agsecres.tool;

import java.io.UnsupportedEncodingException;
import mod.mspr.License;

import agsecres.tool.Shell;

public class Response {

   static String resp = """
<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"><soap:Body><AcquireLicenseResponse xmlns="http://schemas.microsoft.com/DRM/2007/03/protocols"><AcquireLicenseResult><Response xmlns="http://schemas.microsoft.com/DRM/2007/03/protocols/messages"><LicenseResponse xmlns="http://schemas.microsoft.com/DRM/2007/03/protocols"><Version>1</Version><Licenses><License>WE1SAAAAAANtUSgq2MUap8w0LwMciUU0AAMAAQAAAVAAAwACAAAAMgABAA0AAAAKAAEAAAAzAAAACgABAAEAMgAAAAwAAABNAAEANAAAAAoH0AACAAQAAAAIAAMACQAAAPIAAQAKAAAAnlGeAotq1b1EkQ/Utf2Q+6IAAQADAIDe+kG8t08/Zj1Wy+jWeYYwwfFUwpAx0RxYHBhz3hTHO51PZEkwj9dzRKVN7D6Gw0EwpP+fk1Q/Vh7OQNv4ExdIlh91PTpuCPUyKIXt3iOTS/G3zEfIZsnojh/ok4f8GkyDLDbT0YuwI+DfwuImiQ0fWXiwpMXj5iEqApuXh2nKiQAAACoAAABMAAEAQNKWJh5fC/JMwHNNdsgQrO97SSwWBAeKUZxvVFhsv77f6qJs9ynMD3R10iC9z2T6afqe8oDFZvCDw6CA1XDfyg0AAQALAAAAHAABABDl/pk8LYu94zuiIiDk/uaH</License></Licenses><RevInfo><Revocation><ListID>ioydTlK2p0WXkWklprR5Hw==</ListID><ListData>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</ListData></Revocation><Revocation><ListID>gC4IKKPHsUCCVhnlttibJw==</ListID><ListData>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</ListData></Revocation><Revocation><ListID>Ef/RUojT3U6Ct2jqTCChbA==</ListID><ListData>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</ListData></Revocation><Revocation><ListID>BOZ1zT1UnEqfCf5tJOi/kA==</ListID><ListData>PABEAEEAVABBAD4APABJAE4ARABFAFgAPgAxADIAPAAvAEkATgBEAEUAWAA+ADwAVABFAE0AUABMAEEAVABFAD4AQQBBAEEAQQBEAEEAQQBBAEEAQQBPADIASwBvAE4AbQBBADUANAA4AGwAaQBDAC8ANABqAHEARwBJAG4ATQBKACsAawBOAGgAYQA3AEsAZQBWAGcAKwB2AGsAbAB3AFEAVwBIAHUAYwBrADMAKwBpAFoALwBRADIAMABGAHAASwA2AGgARgB2AFIAVgAzAG8AMQB1AFUASgAyAGsAbgB2ACsAYgBiADIAUgB2ADQAZQBxAFgAVQBBAEEAQQBlAGkAUABHAE0ANgBRADIAVgB5AGQARwBsAG0AYQBXAE4AaABkAEcAVgBEAGIAMgB4AHMAWgBXAE4AMABhAFcAOQB1AEkASABoAHQAYgBHADUAegBQAFMASgBvAGQASABSAHcATwBpADgAdgBkADMAZAAzAEwAbgBjAHoATABtADkAeQBaAHkAOAB5AE0ARABBAHcATAB6AEEANQBMADMAaAB0AGIARwBSAHoAYQBXAGMAagBJAGkAQgA0AGIAVwB4AHUAYwB6AHAAagBQAFMASgBvAGQASABSAHcATwBpADgAdgBjADIATgBvAFoAVwAxAGgAYwB5ADUAdABhAFcATgB5AGIAMwBOAHYAWgBuAFEAdQBZADIAOQB0AEwAMABSAFMAVABTADgAeQBNAEQAQQAwAEwAegBBAHkATAAyAE4AbABjAG4AUQBpAEkARwBNADYAVgBtAFYAeQBjADIAbAB2AGIAagAwAGkATQBpADQAdwBJAGoANAA4AFkAegBwAEQAWgBYAEoAMABhAFcAWgBwAFkAMgBGADAAWgBUADQAOABZAHoAcABFAFkAWABSAGgASQBIAGgAdABiAEcANQB6AFAAUwBKAG8AZABIAFIAdwBPAGkAOAB2AGQAMwBkADMATABuAGMAegBMAG0AOQB5AFoAeQA4AHkATQBEAEEAdwBMAHoAQQA1AEwAMwBoAHQAYgBHAFIAegBhAFcAYwBqAEkAaQBCADQAYgBXAHgAdQBjAHoAcABqAFAAUwBKAG8AZABIAFIAdwBPAGkAOAB2AGMAMgBOAG8AWgBXADEAaABjAHkANQB0AGEAVwBOAHkAYgAzAE4AdgBaAG4AUQB1AFkAMgA5AHQATAAwAFIAUwBUAFMAOAB5AE0ARABBADAATAB6AEEAeQBMADIATgBsAGMAbgBRAGkAUABqAHgAagBPAGwAQgAxAFkAbQB4AHAAWQAwAHQAbABlAFQANAA4AFMAMgBWADUAVgBtAEYAcwBkAFcAVQArAFAARgBKAFQAUQBVAHQAbABlAFYAWgBoAGIASABWAGwAUABqAHgATgBiADIAUgAxAGIASABWAHoAUABuAFYASQBSAEUATgBHAFIAVABOAFYAYwBsAEYAQwBiAEcAOQBNAGMAVwBVADIATQAxAEIAWQBlAEQAaABRAGQAbABKAGoATQBTADgAMgBVADAAOAB5AGEAVQBaAE8AVABXAE4AMwBiADMAWgBSAGEAVQBNAHIAVgAwAGgASwBjAG0AUgBIAFYAVwBsADYAYwBUAFIAaQBOADAAVgBVAFoAMwBsAEcAZQBtAEoARQBZAG0AWQB6AFoARABOAEwAYgBpAHMANQBjAEcATgBQAFMAVQB4ADAAYQBqAEoAbgBkAFUATgB0AFQASABGAEYATQBUAGsAdwBjAG0AcABNAFoAVABZADUAUgBGAFYATgBSAFUAUgBEAFIAbQBSAG4ATgBuAGwAUQBTAFUARgBLAFMAMABkAHMAZABVAEYARgBPAEYAcABDAE8AVgBWAGwAWgAzAFoAeQBPAEcAUgBWAGUAVQBOAGgAZQBtAHQAQwBTAFYAQgBMAFkAVgBFADAAUgBqAEYATABVAFcATgBhAFMAbABKAGgAUgAyAE0ANABhAGoARgBQAEsAegBOAEUAVwBHAFIARwBUADMAbAB2AGQARQA5AE0AYQB6ADAAOABMADAAMQB2AFoASABWAHMAZABYAE0AKwBQAEUAVgA0AGMARwA5AHUAWgBXADUAMABQAGsARgBSAFEAVQBJADgATAAwAFYANABjAEcAOQB1AFoAVwA1ADAAUABqAHcAdgBVAGwATgBCAFMAMgBWADUAVgBtAEYAcwBkAFcAVQArAFAAQwA5AEwAWgBYAGwAVwBZAFcAeAAxAFoAVAA0ADgATAAyAE0ANgBVAEgAVgBpAGIARwBsAGoAUwAyAFYANQBQAGoAeABqAE8AawB0AGwAZQBWAFYAegBZAFcAZABsAFAAagB4AGoATwBsAE4AcABaADIANQBEAFUAawB3ACsATQBUAHcAdgBZAHoAcABUAGEAVwBkAHUAUQAxAEoATQBQAGoAdwB2AFkAegBwAEwAWgBYAGwAVgBjADIARgBuAFoAVAA0ADgAWQB6AHAAVABaAFcATgAxAGMAbQBsADAAZQBVAHgAbABkAG0AVgBzAFAAagBBADgATAAyAE0ANgBVADIAVgBqAGQAWABKAHAAZABIAGwATQBaAFgAWgBsAGIARAA0ADgAWQB6AHAATgBZAFcANQAxAFoAbQBGAGoAZABIAFYAeQBaAFgASgBFAFkAWABSAGgAUABqAHgAagBPAGsAMQBoAGIAbgBWAG0AWQBXAE4AMABkAFgASgBsAGMAawA1AGgAYgBXAFUAKwBUAFcAbABqAGMAbQA5AHoAYgAyAFoAMABJAEUATgB2AGMAbgBCAHYAYwBtAEYAMABhAFcAOQB1AFAAQwA5AGoATwBrADEAaABiAG4AVgBtAFkAVwBOADAAZABYAEoAbABjAGsANQBoAGIAVwBVACsAUABHAE0ANgBUAFcARgB1AGQAVwBaAGgAWQAzAFIAMQBjAG0AVgB5AFYAVgBKAE0AUABtAGgAMABkAEgAQQA2AEwAeQA5ADMAZAAzAGMAdQBiAFcAbABqAGMAbQA5AHoAYgAyAFoAMABMAG0ATgB2AGIAVAB3AHYAWQB6AHAATgBZAFcANQAxAFoAbQBGAGoAZABIAFYAeQBaAFgASgBWAFUAawB3ACsAUABDADkAagBPAGsAMQBoAGIAbgBWAG0AWQBXAE4AMABkAFgASgBsAGMAawBSAGgAZABHAEUAKwBQAEMAOQBqAE8AawBSAGgAZABHAEUAKwBQAEYATgBwAFoAMgA1AGgAZABIAFYAeQBaAFQANAA4AFUAMgBsAG4AYgBtAFYAawBTAFcANQBtAGIAegA0ADgAUQAyAEYAdQBiADIANQBwAFkAMgBGAHMAYQBYAHAAaABkAEcAbAB2AGIAawAxAGwAZABHAGgAdgBaAEMAQgBCAGIARwBkAHYAYwBtAGwAMABhAEcAMAA5AEkAbQBoADAAZABIAEEANgBMAHkAOQAzAGQAMwBjAHUAZAB6AE0AdQBiADMASgBuAEwAMQBSAFMATAB6AEkAdwBNAEQARQB2AFUAawBWAEQATABYAGgAdABiAEMAMQBqAE0AVABSAHUATABUAEkAdwBNAEQARQB3AE0AegBFADEASQBqADQAOABMADAATgBoAGIAbQA5AHUAYQBXAE4AaABiAEcAbAA2AFkAWABSAHAAYgAyADUATgBaAFgAUgBvAGIAMgBRACsAUABGAE4AcABaADIANQBoAGQASABWAHkAWgBVADEAbABkAEcAaAB2AFoAQwBCAEIAYgBHAGQAdgBjAG0AbAAwAGEARwAwADkASQBtAGgAMABkAEgAQQA2AEwAeQA5AHoAWQAyAGgAbABiAFcARgB6AEwAbQAxAHAAWQAzAEoAdgBjADIAOQBtAGQAQwA1AGoAYgAyADAAdgBSAEYASgBOAEwAegBJAHcATQBEAFEAdgBNAEQASQB2AFEAMABWAFMAVgBDADkAUwBjADIARQB0AGMAMgBoAGgATQBTAEkAKwBQAEMAOQBUAGEAVwBkAHUAWQBYAFIAMQBjAG0AVgBOAFoAWABSAG8AYgAyAFEAKwBQAEYASgBsAFoAbQBWAHkAWgBXADUAagBaAFQANAA4AFYASABKAGgAYgBuAE4AbQBiADMASgB0AGMAegA0ADgAVgBIAEoAaABiAG4ATgBtAGIAMwBKAHQASQBFAEYAcwBaADIAOQB5AGEAWABSAG8AYgBUADAAaQBhAEgAUgAwAGMARABvAHYATAAzAE4AagBhAEcAVgB0AFkAWABNAHUAYgBXAGwAagBjAG0AOQB6AGIAMgBaADAATABtAE4AdgBiAFMAOQBFAFUAawAwAHYATQBqAEEAdwBOAEMAOAB3AE0AaQA5AEQAUgBWAEoAVQBMADAAUgBoAGQARwBFAGkAUABqAHcAdgBWAEgASgBoAGIAbgBOAG0AYgAzAEoAdABQAGoAeABVAGMAbQBGAHUAYwAyAFoAdgBjAG0AMABnAFEAVwB4AG4AYgAzAEoAcABkAEcAaAB0AFAAUwBKAG8AZABIAFIAdwBPAGkAOAB2AGQAMwBkADMATABuAGMAegBMAG0AOQB5AFoAeQA5AFUAVQBpADgAeQBNAEQAQQB4AEwAMQBKAEYAUQB5ADEANABiAFcAdwB0AFkAegBFADAAYgBpADAAeQBNAEQAQQB4AE0ARABNAHgATgBTAEkAKwBQAEMAOQBVAGMAbQBGAHUAYwAyAFoAdgBjAG0AMAArAFAAQwA5AFUAYwBtAEYAdQBjADIAWgB2AGMAbQAxAHoAUABqAHgARQBhAFcAZABsAGMAMwBSAE4AWgBYAFIAbwBiADIAUQBnAFEAVwB4AG4AYgAzAEoAcABkAEcAaAB0AFAAUwBKAG8AZABIAFIAdwBPAGkAOAB2AGQAMwBkADMATABuAGMAegBMAG0AOQB5AFoAeQA4AHkATQBEAEEAdwBMAHoAQQA1AEwAMwBoAHQAYgBHAFIAegBhAFcAYwBqAGMAMgBoAGgATQBTAEkAKwBQAEMAOQBFAGEAVwBkAGwAYwAzAFIATgBaAFgAUgBvAGIAMgBRACsAUABFAFIAcABaADIAVgB6AGQARgBaAGgAYgBIAFYAbABQAGsAZABLAGIAVgBSAFoAYQBGAFoANQBXAFgAcABwAFQAVwB4ADQAYwBuAEIAUABNAG0AYwB4AFoAMgB4AEQAWgBIAGwASgBOAEQAMAA4AEwAMABSAHAAWgAyAFYAegBkAEYAWgBoAGIASABWAGwAUABqAHcAdgBVAG0AVgBtAFoAWABKAGwAYgBtAE4AbABQAGoAdwB2AFUAMgBsAG4AYgBtAFYAawBTAFcANQBtAGIAegA0ADgAVQAyAGwAbgBiAG0ARgAwAGQAWABKAGwAVgBtAEYAcwBkAFcAVQArAGEAVwB0AFIAVgBtADkAWABjADAAWgBZAGQAMgBaAEcATQAwAE4ASgBiADAAMQAzAFYAbABRADAAZQBIAHAASgBVAFgAYwB2AFEAegBkADQAUQBWAGwATABMADMAZwB2AE4ARABGAHYAZQBYAGgASwBLADEASQB4AFUAbQBjAHcAYwAxAEYAdQBkAGwAUQAyAFIAVwBjAHIAWgBuAE4ARQBRADEAQgBtAGQAbABwAHgAVQBEAGcAeABNADEAbABXAE4AMABJADMAUgBGAFYANQBiADIAZABqAGQAMgBVAHcAYQAxAFEAeQBRADAARgBuAFQAVQB4AEsAUwBXAHQAWQBVADEAYwAxAGUAVwBkAEIAWgAxAGMANQBTAFUAcABTAE8ASABNADIAUgBHAEYAaABWADIAYwB6AE0AVQBWAHUAYQBuAGgARABWAEgAUgBsAGIARQBkAHQATgBsAGwAMgBOAEUAbABIAGIAVwBoAHoAZQBEAEoAbwBNAFUARgBpAE0AbQBsAGgAYwBrAEkAMwBhAG0AUQB3AE0ARABSAFkAWQBsAHAAeQBjAFgAbwB3AGUAVABkAFUATQBWAEkANABNAEUAbwA0AFAAVAB3AHYAVQAyAGwAbgBiAG0ARgAwAGQAWABKAGwAVgBtAEYAcwBkAFcAVQArAFAARQB0AGwAZQBVAGwAdQBaAG0AOAArAFAARQB0AGwAZQBWAFoAaABiAEgAVgBsAFAAagB4AFMAVQAwAEYATABaAFgAbABXAFkAVwB4ADEAWgBUADQAOABUAFcAOQBrAGQAVwB4ADEAYwB6ADUAdwBhAG0AOQBsAFYAMAB4AFQAVgBFAHgARQBiADIANQBSAFIAegBoAFQAYQBHAFUAMgBVAFcAaAByAFcAVwBKAFoAYgAzAFIAMABPAFcAWgBRAFcAagBoADAAUwBHAFIAQwBNAFQASQA0AFcAawBWAFUAWQAyAGQAbwBiAGoAVgBMAFMARwA5ADUAYQBXADQAMwBTAEcAdABLAFIAVwBOAFEAUwBqAEIARgBaAHoAUgBWAFoARgBOADIAWQBUAEIATABSAEUAbABaAFIARwBwAEIATQAwAFYAWQBaAEQAWQA1AFUAagBOAEQAVABqAEoAWABjAEMAOQBSAGUAVQA5AHYATQBGAHAAUQBXAFYAZABaAGMARABOAE8AVwBIAEIASwBOAHoAQQB3AGQARQB0AFEAWgAwAGwAdwBiAEgAcAB2AE4AWABkAFcAWgBDADgAMgBPAFcAYwAzAGEAaQB0AHEATwBFADAAMgBOAGwAYwAzAFYAawA1AHQAUgBIAGQAaABUAG4ATQA1AGIAVQBSAGoATQBYAEEAeQBLADEAWgBXAFQAWABOAEUAYQBFADkAegBWAGkAOQBCAGQAVABaAEYASwAwAFUAOQBQAEMAOQBOAGIAMgBSADEAYgBIAFYAegBQAGoAeABGAGUASABCAHYAYgBtAFYAdQBkAEQANQBCAFUAVQBGAEMAUABDADkARgBlAEgAQgB2AGIAbQBWAHUAZABEADQAOABMADEASgBUAFEAVQB0AGwAZQBWAFoAaABiAEgAVgBsAFAAagB3AHYAUwAyAFYANQBWAG0ARgBzAGQAVwBVACsAUABDADkATABaAFgAbABKAGIAbQBaAHYAUABqAHcAdgBVADIAbABuAGIAbQBGADAAZABYAEoAbABQAGoAdwB2AFkAegBwAEQAWgBYAEoAMABhAFcAWgBwAFkAMgBGADAAWgBUADQAOABMADIATQA2AFEAMgBWAHkAZABHAGwAbQBhAFcATgBoAGQARwBWAEQAYgAyAHgAcwBaAFcATgAwAGEAVwA5AHUAUABnAEkAQQBnAEIAZwBBAHoAUwBKAHoAawB0AEIAagBoAG4ALwBDAFkAdABTAHgAbQBjAFAAOAAwAGcAZgBmAHkAdABUAHcAdwBoAEoAUQArAEUASABHAHMAcABJAEYAZwAvAEEAbgAvAG4ANQA3AEQARwBiAEcATwBQAGwAOQAwAG8AQgBhAHIAeQBpADIAQQBIAE0AbABRAEwAOQB1ADcAegBJAGMANABKAGIAYwBRAEIASQBkAG0ATAB3AGUAUgBlAG4ATwAvADAAVgBVAGEAVgBEAHcAWgBzAHAAdAB0ADYAMQBoAGoATwBXAE0AQQBMAHcAMQBWACsANwBpADQARABEAEcAaABHAHAAbQB2AEEANABBAHoAUgBLAFgANQArAFAAZgBnADAAUABMAEQAOABGAHQARQA4AHIATQBBADUATAB1AGUAOAA4AHIAOQBiAHAAMQBYAFQAdAAwADwALwBUAEUATQBQAEwAQQBUAEUAPgA8AC8ARABBAFQAQQA+ADwAUwBJAEcATgBBAFQAVQBSAEUAPgA8AEgAQQBTAEgAQQBMAEcATwBSAEkAVABIAE0AIAB0AHkAcABlAD0AIgBTAEgAQQAiAD4APAAvAEgAQQBTAEgAQQBMAEcATwBSAEkAVABIAE0APgA8AFMASQBHAE4AQQBMAEcATwBSAEkAVABIAE0AIAB0AHkAcABlAD0AIgBNAFMARABSAE0AIgA+ADwALwBTAEkARwBOAEEATABHAE8AUgBJAFQASABNAD4APABWAEEATABVAEUAPgB2AFgAaABzAEYAWQBhAFoAQgB5AHgARABnAFMATgB5AFAANABEAHIAOQBZAGkARQBsAEIASwBOAHYAVwBxAGcAeABQAFoAbgBkAFYAZABJAGcAdgA3AEEAUAAxAHUASgAxADAAOQBtAFYAQQA9AD0APAAvAFYAQQBMAFUARQA+ADwALwBTAEkARwBOAEEAVABVAFIARQA+AA==</ListData></Revocation></RevInfo></LicenseResponse></Response></AcquireLicenseResult></AcquireLicenseResponse></soap:Body></soap:Envelope>""";

   public static void main(String args[]) {
      Vars.set("MAC", "AABBCCDDEEFF");
      Vars.set("MSPR_DEBUG", 1);
      Vars.set("SERIAL", "DGBD0123456789ABC");
      
      try {
         byte license_xml[] = resp.getBytes("UTF-8");
         License hello = new License(license_xml);
         System.out.println(hello);
         byte[] key = hello.get_content_key();
         // <KID>UZ4Ci2rVvUSRD9S1/ZD7og==</KID>
         // 519e028b6ad5bd44910fd4b5fd90fba2
         // key:
         // c8 89 cc a2 5e b3 0b 3b 12 8e b8 34 ea 4d a4 fa
         Shell.get_pp().printhex("", key);
      } catch (UnsupportedEncodingException err) {
         System.err.println(err);
      }
   }
   
}
