
rule malicious login.php {
   meta:
      description = "Demo Rule"
      author = "Ainthacker"
      reference = "N/A"
      date = "2025-06-04"
   strings:
      $s0 = "MSXML2.XMLHTTP" fullword ascii
      $s1 = "Scripting.FileSystemObject" fullword ascii
      $s2 = "ADODB.Stream" fullword ascii
      $s3 = "WScript.Shell" fullword ascii
      $s4 = "Run(" fullword ascii
      $s5 = "GetSpecialFolder(2)" fullword ascii
      $s6 = "ResponseBody" fullword ascii
      $s7 = "SaveToFile" fullword ascii
      $s8 = "open(\"GET" fullword ascii
      $s9 = "ActiveXObject" fullword ascii
      $s10 = "Close()" fullword ascii
   condition:
      any of ($s1, $s2, $s3) and $s4
}
