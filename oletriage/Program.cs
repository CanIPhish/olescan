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
        private static string oleFile;
        private static string outFile;

        static void Main(string[] args)
        {
            if (args.Length == 0) { HelpMessage(); }
            else
            {
                oleFile = args[args.Length - 1];
                Parser.Default.ParseArguments<Options>(args)
                   .WithParsed<Options>(o =>
                   {
                       if (o.help) { HelpMessage(); }
                       else
                       {
                           outFile = o.output;
                           if(o.batch) { BatchAnalysis(oleFile, o.quiet); }
                           else
                           {
                               PerformAnalysis(oleFile, o.quiet);
                           }
                       }
                   });
            }
        }

        private static void BatchAnalysis (string batchFile, bool triage)
        {
            string[] files = new StreamReader(batchFile).ReadToEnd().Split(new string[] { "\r\n" },StringSplitOptions.RemoveEmptyEntries);
            foreach (string file in files)
            {
                PerformAnalysis(file, triage);
            }
        }

        private static void SaveOutput (ContentAnalysis cAnalysis)
        {
            using (var sw = new StreamWriter(outFile))
            {
                var csvWriter = new CsvWriter(sw);
                //Now we will write the data into the same output file but will do it 
                //Using two methods.  The first is writing the entire record.  The second
                //method writes individual fields.  Note you must call NextRecord method after 
                //using Writefield to terminate the record.

                //Note that WriteRecords will write a header record for you automatically.  If you 
                //are not using the WriteRecords method and you want to a header, you must call the 
                //Writeheader method like the following:
                //
                //writer.WriteHeader<DataRecord>();
                //
                //Do not use WriteHeader as WriteRecords will have done that already.
                //csvWriter.WriteField(oleFile);
                if(cAnalysis != null)
                {
                    csvWriter.WriteField(cAnalysis.docType);
                    csvWriter.WriteField(cAnalysis.olevbaMacro);
                    csvWriter.WriteField(cAnalysis.olevbaAutoExecutable);
                    csvWriter.WriteField(cAnalysis.olevbaSuspiciousKeywords);
                    csvWriter.WriteField(cAnalysis.olevbaIOCs);
                    csvWriter.WriteField(cAnalysis.olevbaHexStrings);
                    csvWriter.WriteField(cAnalysis.olevbaBase64Strings);
                    csvWriter.WriteField(cAnalysis.olevbaDridexStrings);
                    csvWriter.WriteField(cAnalysis.olevbaVbaStrings);
                    csvWriter.WriteField(cAnalysis.mraptorFlags);
                    csvWriter.WriteField(cAnalysis.mraptorSuspicious);
                    csvWriter.WriteField(cAnalysis.docType);
                    csvWriter.NextRecord();
                }
            }
        }

        private static void PerformAnalysis(string oleFile, bool triage)
        {
            ContentDetection contentDetection = new ContentDetection();
            if (contentDetection.DetectOLEContent(oleFile))
            {
                ContentAnalysis contentAnalysis = new ContentAnalysis();
                contentAnalysis.ScanOLEContent(oleFile, triage);
                SuspicionScoring suspicionScore = new SuspicionScoring();
                Console.WriteLine("Suspicion Score: " + suspicionScore.SuspicionAnalysis(contentAnalysis).ToString("#0.##%"));
                if (outFile != "") { SaveOutput(contentAnalysis); }
            }
            else
            {
                Console.WriteLine("No VBA Contents");
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
                    "0 - 15 % - RARE\n" +
                    "16 - 39 % - UNLIKELY\n" +
                    "40 - 60 % - POSSIBLE\n" +
                    "61 - 84 % - LIKELY\n" +
                    "85 - 100 % - ALMOST CERTAIN\n" +
                    "It's recommended that anything rated above 15% be investigated further. Please see \n" +
                    "(https://github.com/decalage2/oletools) and/or (https://github.com/decalage2/ViperMonkey) \n" +
                    "for extremely useful analysis tools.\n\n" +
                    "\nUsage: olescan [Options] <filename>" +
                    "\nOptions:" +
                    "\n-h, --help         show help message and exit" +
                    "\n-b, --batch        input a pipe delimited list in-place of <filename> for scanning automation" +
                    "\n-o, --output       output scanning results into a comma delimited file (e.g. -o \"C:\\results.csv\")" +
                    "\n\n" +
                    "Example Usage: olescan -q -l -o \"C:\\Results.csv\" \"C:\\DocumentList.csv\"");
        }

    }
}
