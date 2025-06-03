
rule first {
   meta:
      description = "Custom rule created by user input"
      author = "tural"
      reference = "https://any.run/malware-trends/quasar/"
      date = "2025-06-03"
   strings:
      $s0 = "146.190.29.250" fullword ascii
      $s1 = "217.195.197.132" fullword ascii
      $s2 = "213.209.143.58" fullword ascii
      $s3 = "45.202.35.187" fullword ascii
      $s4 = "86.11.53.138" fullword ascii
      $s5 = "193.161.193.99" fullword ascii
      $s6 = "51.91.251.234" fullword ascii
      $s7 = "70.34.210.80" fullword ascii
      $s8 = "118.195.162.44" fullword ascii
      $s9 = "73.62.14.5" fullword ascii
      $s10 = "147.185.221.19" fullword ascii
      $s11 = "tcp://scriptdagoat-21700.portmap.io:21700/" fullword ascii
      $s12 = "http://freegeoip.net/xml/" fullword ascii
      $s13 = "http://telize.com/geoip" fullword ascii
      $s14 = "http://silly1.duckdns.org:8888/" fullword ascii
      $s15 = "tcp://0.tcp.eu.ngrok.io:15869/" fullword ascii
      $s16 = "http://binance.com/" fullword ascii
      $s17 = "http://1.199.158.213.in-addr.arpa:49669/" fullword ascii
      $s18 = "tcp://0.tcp.ap.ngrok.io:16495/" fullword ascii
      $s19 = "http://18.134.234.207/update/ping" fullword ascii
      $s20 = "http://18.134.234.207/update/error" fullword ascii
      $s21 = "http://18.134.234.207/update/report" fullword ascii
      $s22 = "tcp://6.tcp.eu.ngrok.io:16451/" fullword ascii
      $s23 = "http://church-apr.gl.at.ply.gg/:31194" fullword ascii
      $s24 = "https://discordinit.ddns.net:4782/" fullword ascii
      $s25 = "http://www.telize.com/geoip" fullword ascii
      $s26 = "tcp://6.tcp.eu.ngrok.io:16457/" fullword ascii
      $s27 = "tcp://2.tcp.eu.ngrok.io:14336/" fullword ascii
      $s28 = "tcp://6.tcp.eu.ngrok.io:10324/" fullword ascii
   condition:
      any of them
}
