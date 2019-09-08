# olescan

THIS IS A WORK IN PROGRESS - Check updates regularly!

olescan is a lightweight wrapper aggregating the functionality of several oletools
to facilitate automated scanning of MS OLE2 and MS Office documents. The tool is
not designed to cover advanced maldoc analysis but is to assist Level 1 Support Teams
in performing a preliminary analysis before escalating to Level 2/3 Support Teams (i.e. InfoSec Professionals).

It's analysis capabilities include:
   1. Scanning of macro-enabled file-types and detection of macros, embedded flash content or
      file encryption (oleid)
   2. Automatic code extraction, VBA stomping detection, decoding of common obfuscation
      methods including Hex encoding, StrReverse, Base64, Dridex, VBA expressions, and
      identification of IOCs from decoded strings (olvevba)
   3. Scanning and detection of malicious VBA Macros using generic heuristics to check for
      auto - execution, system / memory writes and / or file execution outside the VBA context (mraptor)

Analysis Result: olescan will provide a suspicious rating between 0-100%

Key:
0-24% - RARE
25-49% - UNLIKELY
50-74% - POSSIBLE
75-89% - LIKELY
90-100% - ALMOST CERTAIN

It's my recommendation that anything above 24% be investigated further. Please see (https://github.com/decalage2/oletools) 
and/or (https://github.com/decalage2/ViperMonkey) for extremely useful macro analysis tools.

Usage: olescan [Options] \<filename>

Options:

      -h, --help         show this help message and exit

      -i, --input        input a delimited text file in-place of <filename> for scanning automation

      -o, --output       output scanning results into a delimited text file (e.g. -o "C:\results.csv")

      -q, --quiet        simple analysis result of SUSPICIOUS rating or CLEAN


Example Usage: olescan -q -i -o "C:\Results.csv" "C:\DocumentList.csv"
