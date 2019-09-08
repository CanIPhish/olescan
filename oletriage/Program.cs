using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace olescan
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 1)
            {
                HelpMessage();
            }
            else
            {
                ContentDetection contentDetection = new ContentDetection();
                if(contentDetection.DetectOLEContent(args[0]))
                {
                    ContentAnalysis contentAnalysis = new ContentAnalysis();
                    contentAnalysis.ScanOLEContent(args[0],true);
                    SuspicionScoring suspicionScore = new SuspicionScoring();
                    Console.WriteLine("Suspicion Score: " + suspicionScore.SuspicionAnalysis(contentAnalysis).ToString("#0.##%"));
                }
            }
        }

        private static void HelpMessage()
        {
            Console.WriteLine("olescan 0.01 - see https://github.com/Rices/olescan for updates " +
                    "\nTHIS IS A WORK IN PROGRESS - Check updates regularly! \n\n" +
                    "olescan is a lightweight wrapper aggregating the functionality of several oletools \n" +
                    "to facilitate automated scanning of MS OLE2 and MS Office documents. The tool is \n" +
                    "not designed to cover advanced maldoc analysis but is to assist Level 1 Support Teams \n" +
                    "in performing a preliminary analysis before escalating to Level 2 Support Teams (i.e. InfoSec Professional)." +
                    "\n\nIt's analysis capabilities include:\n" +
                    "1. Scanning of macro-enabled file-types and detection of macros, embedded flash content or \n" +
                    "   file encryption (oleid)\n" +
                    "2. Automatic code extraction, VBA stomping detection, decoding of common obfuscation \n" +
                    "   methods including Hex encoding, StrReverse, Base64, Dridex, VBA expressions, and \n" +
                    "   identification of IOCs from decoded strings (olvevba)\n" +
                    "3. Scanning and detection of malicious VBA Macros using generic heuristics to check for \n" +
                    "   auto - execution, system / memory writes and / or file execution outside the VBA context (mraptor)\n\n" +
                    "Analysis Result: olescan will provide a suspicious rating between 0 - 100 %\n\n" +
                    "Key:\n" +
                    "0 - 24 % - RARE\n" +
                    "25 - 49 % - UNLIKELY\n" +
                    "50 - 74 % - POSSIBLE\n" +
                    "75 - 89 % - LIKELY\n" +
                    "90 - 100 % - ALMOST CERTAIN\n" +
                    "It's my recommendation that anything above 24% be investigated further. Please see \n" +
                    "(https://github.com/decalage2/oletools) and/or (https://github.com/decalage2/ViperMonkey) \n" +
                    "for extremely useful macro analysis tools.\n\n" +
                    "\nUsage: olescan [Options] <filename>" +
                    "\nOptions:" +
                    "\n-h, --help         show this help message and exit" +
                    "\n-i, --input        input a delimited text file in-place of <filename> for scanning automation" +
                    "\n-o, --output       output scanning results into a delimited text file (e.g. -o \"C:\\results.csv\")" +
                    "\n-q, --quiet        simple analysis result of SUSPICIOUS or CLEAN" +
                    "\n\n" +
                    "Example Usage: olescan -q -i -o \"C:\\Results.csv\" \"C:\\DocumentList.csv\"");
        }

    }
}
