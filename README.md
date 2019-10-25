# olescan

olescan is a lightweight wrapper aggregating the functionality of several oletools
to facilitate automated scanning of MS OLE2 and MS Office documents. The tool is
not designed to cover advanced maldoc analysis but is to assist Level 1 Support Teams
in performing a preliminary analysis before escalating to Level 2/3 Support Teams (i.e. InfoSec Professionals).

It's analysis capabilities include:
   1. Scanning of macro-enabled file-types and detection of macros, embedded flash content or
      file encryption (oleid)
   2. Automatic code extraction, VBA stomping detection, decoding of common obfuscation
      methods including Hex encoding, StrReverse, Base64, Dridex, VBA expressions, and
      identification of IOCs and suspicious VBA keywords from decoded strings (olvevba)
   3. Scanning and detection of malicious VBA Macros using generic heuristics to check for
      auto - execution, system / memory writes and / or file execution outside the VBA context (mraptor)

Setup:
Requires a Windows OS and installation of the oletools utility. Please see https://github.com/decalage2/oletools/wiki/Install. 
Tested on Windows 10 using olevba 0.54.2/0.55.dev3 on Python 3.7.4

Analysis Result: olescan will provide a suspicion rating between 0-100%

Key:

	0-15% - RARE

	16-40% - UNLIKELY

	41-59% - POSSIBLE

	60-84% - LIKELY

	85-100% - ALMOST CERTAIN


It's recommended that anything above 40% be investigated further. Please see (https://github.com/decalage2/oletools) 
and/or (https://github.com/decalage2/ViperMonkey) for extremely useful analysis tools.

Usage: olescan [Options] \<filename>

Options:

      -h, --help         show help message and exit

      -b, --batch        input a pipe delimited list in-place of <filename> for scanning automation

      -o, --output       output scanning results into a delimited text file (e.g. -o "C:\results.csv")

	  -v, --verbose		output the verbose analysis to console


Example Usage: olescan -v -b -o "C:\Results.csv" "C:\DocumentList.csv"
