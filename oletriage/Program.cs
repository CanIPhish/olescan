using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace oletriage
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 1)
            {
                Console.WriteLine("oletriage 0.01 - see https://github.com/Rices/oletriage for updates " +
                    "\nTHIS IS A WORK IN PROGRESS - Check updates regularly! \n\n" +
                    "oletriage is a lightweight wrapper aggregating the functionality of several tools \n" +
                    "to facilitate automated scanning of MS OLE2 and MS Office documents. The tool is \n" +
                    "not designed to cover advanced maldoc analysis but is to assist Level 1 Support Teams \n" +
                    "in performing basic code analysis before escalating to Level 2 Support Teams (i.e. InfoSec Professional)." +
                    "\n\nIts analysis capabilities include:\n" +
                    "1. Scanning of macro-enabled file-types and detection of macros, embedded flash content or \n" +
                    "   file encryption (oleid)\n" +
                    "2. Automatic code extraction, VBA stomping detection, decoding of common obfuscation \n" +
                    "   methods including Hex encoding, StrReverse, Base64, Dridex, VBA expressions, and \n" +
                    "   identification of IOCs from decoded strings (olvevba)\n" +
                    "3. Scanning of both encoded and decoded strings against YARA rules(olevba + yara)\n" +
                    "4. Scanning and detection of malicious VBA Macros using generic heuristics to check for \n" +
                    "   auto - execution, system / memory writes and / or file execution outside the VBA context (mraptor)\n" +
                    "\nUsage: oletriage [Options] <filename>" +
                    "\nOptions:" +
                    "\n-h, --help         show this help message and exit" +
                    "\n-r, --recurse      find files recursively in subdirectories" +
                    "\n-i, --input        input a delimited text file in-place of <filename> for scanning automation" +
                    "\n-o, --output       output scanning results into a delimited text file (e.g. -o \"C:\\results.csv\")" +
                    "\n-q, --quiet        simple analysis result of SUSPICIOUS or CLEAN" +
                    "\n\n" +
                    "Example Usage: oletriage -q -i -o \"C:\\Results.csv\" \"C:\\DocumentList.csv\"");
            }
            else
            {

                ContentDetection contentDetection = new ContentDetection();
                string test = Console.ReadLine();
                Console.WriteLine(test);
                contentDetection.DetectOLEContent(test);
            }
        }
    }
}
