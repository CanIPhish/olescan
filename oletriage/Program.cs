using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using CsvHelper;

namespace olescan
{
    class Program
    {
        private static string outFile;

        static void Main(string[] args)
        {
            if (args.Length == 0) { HelpMessage(); }
            else
            {
                string oleFile = args[args.Length - 1];
                Parser.Default.ParseArguments<Options>(args)
                   .WithParsed<Options>(o =>
                   {
                       if (o.help) { HelpMessage(); }
                       else
                       {
                           outFile = o.output;
                           if(o.batch) { BatchAnalysis(oleFile, o.verbose); }
                           else
                           {
                               PerformAnalysis(oleFile, o.verbose);
                           }
                       }
                   });
            }
        }

        private static void BatchAnalysis (string batchFile, bool verbose)
        {
            string[] files = new StreamReader(batchFile).ReadToEnd().Split(new string[] { "\r\n" },StringSplitOptions.RemoveEmptyEntries);
            foreach (string file in files)
            {
                PerformAnalysis(file, verbose);
            }
        }

        private static void SaveOutput (ContentAnalysis cAnalysis, string macroFile, string sScore)
        {
            bool outFileExists = File.Exists(outFile);
            using (StreamWriter outWriter = new StreamWriter(outFile, true))
            {
                if (!outFileExists) {
                    outWriter.WriteLine("Document_Name,Macro_Detected,Macro_AutoExec,Macro_Suspicious_Keywords,Macro_IOCs," +
                    "Macro_Hex_Encoding,Macro_Base64_Encoding,Macro_Dridex_Encoding,Macro_VBAString_Encoding," +
                    "Macro_mraptor_flags,Macro_mraptor_suspicious,Error_Flag,Suspicion_Score");
                }
                outWriter.Write(macroFile + ",");
                outWriter.Write(cAnalysis.olevbaMacro + ",");
                outWriter.Write(cAnalysis.olevbaAutoExecutable + ",");
                outWriter.Write(cAnalysis.olevbaSuspiciousKeywords + ",");
                outWriter.Write(cAnalysis.olevbaIOCs + ",");
                outWriter.Write(cAnalysis.olevbaHexStrings + ",");
                outWriter.Write(cAnalysis.olevbaBase64Strings + ",");
                outWriter.Write(cAnalysis.olevbaDridexStrings + ",");
                outWriter.Write(cAnalysis.olevbaVbaStrings + ",");
                outWriter.Write(cAnalysis.mraptorFlags + ",");
                outWriter.Write(cAnalysis.mraptorSuspicious + ",");
                outWriter.Write(cAnalysis.errorFlag + ",");
                outWriter.WriteLine(sScore);
            }
        }

        private static void PerformAnalysis(string oleFile, bool verbose)
        {
            try
            {
                ContentDetection contentDetection = new ContentDetection();
                if (contentDetection.DetectOLEContent(oleFile))
                {
                    ContentAnalysis contentAnalysis = new ContentAnalysis();
                    contentAnalysis.ScanOLEContent(oleFile);
                    SuspicionScoring suspicionScore = new SuspicionScoring();
                    string sScore = suspicionScore.SuspicionAnalysis(contentAnalysis).ToString("#0.##%");
                    if (verbose)
                    {
                        VerboseMessage(contentAnalysis, oleFile, sScore);
                    }
                    else
                    {
                        Console.WriteLine("Scan Errors: " + contentAnalysis.errorFlag + "   Suspicion Score: " + sScore);
                    }
                    if (outFile != "") { SaveOutput(contentAnalysis, oleFile, sScore); }
                }
                else
                {
                    Console.WriteLine("No VBA Contents");
                }
            }
            catch
            {
                Console.WriteLine("An error occured scanning this file");
            }
        }

        private static void VerboseMessage(ContentAnalysis contentAnalysis, string oleFile, string sScore)
        {
            Console.WriteLine("Suspicion Score: " + sScore);
            Console.WriteLine("\n--- mraptor Output ---\n");
            Console.WriteLine(contentAnalysis.fullmraptorOutput);
            Console.WriteLine("\n--- olevba Output ---\n");
            Console.WriteLine(contentAnalysis.fullolevbaOutput);
            Console.WriteLine("------------------------------------------------------------------------------------------");
            Console.WriteLine("------------------------------------------------------------------------------------------");
        }

        private static void HelpMessage()
        {
            Console.WriteLine("olescan 0.01 - see https://github.com/Rices/olescan for updates \n\n" +
                    "olescan is a lightweight wrapper aggregating the functionality of several oletools \n" +
                    "to facilitate automated scanning of MS OLE2 and MS Office documents. The tool is \n" +
                    "not designed to cover advanced maldoc analysis but is to assist Level 1 Support Teams \n" +
                    "in performing a preliminary analysis before escalating to Level 2 Support Teams (i.e. InfoSec Professional)." +
                    "\n\nIt's analysis capabilities include:\n" +
                    "1. Scanning of macro-enabled file-types and detection of macros, embedded flash content or \n" +
                    "   file encryption (oleid)\n" +
                    "2. Automatic code extraction, VBA stomping detection, decoding of common obfuscation \n" +
                    "   methods including Hex encoding, StrReverse, Base64, Dridex, VBA expressions, and \n" +
                    "   identification of IOCs and suspicious VBA keywords from decoded strings (olvevba)\n" +
                    "3. Scanning and detection of malicious VBA Macros using generic heuristics to check for \n" +
                    "   auto - execution, system / memory writes and / or file execution outside the VBA context (mraptor)\n\n" +
                    "Analysis Result: olescan will provide a suspicion rating between 0 - 100 %\n\n" +
                    "Key:\n" +
                    "0 - 15 % - RARE\n" +
                    "16 - 40 % - UNLIKELY\n" +
                    "41 - 59 % - POSSIBLE\n" +
                    "60 - 84 % - LIKELY\n" +
                    "85 - 100 % - ALMOST CERTAIN\n" +
                    "Please see (https://github.com/decalage2/oletools) and/or (https://github.com/decalage2/ViperMonkey) \n" +
                    "for extremely useful analysis tools.\n\n" +
                    "\nUsage: olescan [Options] <filename>" +
                    "\nOptions:" +
                    "\n-h, --help         show help message and exit" +
                    "\n-b, --batch        input a pipe delimited list in-place of <filename> for scanning automation" +
                    "\n-o, --output       output scanning results into a comma delimited file (e.g. -o \"C:\\results.csv\")" +
                    "\n-v, --verbose      output the verbose analysis to console" +
                    "\n\n" +
                    "Example Usage: olescan -v -b -o \"C:\\Results.csv\" \"C:\\DocumentList.csv\"");
        }

    }
}
