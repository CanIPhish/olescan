using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace olescan
{
    class ContentAnalysis
    {
        public string fullolevbaOutput;
        public string fullmraptorOutput;
        public string docType;
        public bool olevbaMacro;
        public bool olvevbaAutoExecutable;
        public bool olevbaSuspiciousKeywords;
        public bool olvevbaIOCs;
        public bool olevbaHexStrings;
        public bool olevbaBase64Strings;
        public bool olevbaDridexStrings;
        public bool olevbaVbaStrings;
        public bool mraptorSuspicious;
        public string mraptorFlags;
        

        public void ScanOLEContent(string fileName, bool triage)
        {
            OlevbaScan(fileName, triage);
            MraptorScan(fileName);
        }

        public void MraptorScan(string fileName)
        {
            //Close process when execution chain is finished
            using (Process process = new Process())
            {
                //Call the mraptor executable within the users environment variables
                process.StartInfo.FileName = "mraptor";
                string argument = '\"' + fileName + '"';
                process.StartInfo.Arguments = argument;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.Start();

                // Synchronously read the standard output of the spawned process. 
                StreamReader reader = process.StandardOutput;
                //Console.WriteLine(reader.ReadToEnd());
                fullmraptorOutput = reader.ReadToEnd();
                string[] output = fullmraptorOutput.Split(Environment.NewLine.ToCharArray());

                process.WaitForExit();
                ParsemraptorOutput(output);
            }
        }

        public void ParsemraptorOutput(string[] mraptorOutput)
        {
            mraptorSuspicious = mraptorOutput[18].Contains("SUSPICIOUS");
            mraptorFlags = mraptorOutput[10].Substring(11, 3);
        }

        public void OlevbaScan(string fileName, bool triage)
        {
            //Close process when execution chain is finished
            using (Process process = new Process())
            {
                //Call the olevba executable within the users environment variables
                process.StartInfo.FileName = "olevba";
                string argument = '\"' + fileName + '"';
                if (triage) { argument = "-t " + argument; }
                process.StartInfo.Arguments = argument;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.Start();

                // Synchronously read the standard output of the spawned process. 
                StreamReader reader = process.StandardOutput;
                fullolevbaOutput = reader.ReadToEnd();
                string[] output = fullolevbaOutput.Split(Environment.NewLine.ToCharArray());

                process.WaitForExit();
                ParseolevbaOutput(output);
            }
        }

        public void ParseolevbaOutput(string[] olevbaOutput)
        {
            docType = olevbaOutput[6].Substring(0, 3);
            olevbaMacro = !olevbaOutput[6].Substring(4, 1).Contains("-");
            olvevbaAutoExecutable = !olevbaOutput[6].Substring(5, 1).Contains("-");
            olevbaSuspiciousKeywords = !olevbaOutput[6].Substring(6, 1).Contains("-");
            olvevbaIOCs = !olevbaOutput[6].Substring(7, 1).Contains("-");
            olevbaHexStrings = !olevbaOutput[6].Substring(8, 1).Contains("-");
            olevbaBase64Strings = !olevbaOutput[6].Substring(9, 1).Contains("-");
            olevbaDridexStrings = !olevbaOutput[6].Substring(10, 1).Contains("-");
            olevbaVbaStrings = !olevbaOutput[6].Substring(11, 1).Contains("-");
        }
    }
}
