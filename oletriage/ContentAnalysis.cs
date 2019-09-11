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
        internal string fullolevbaOutput;
        internal string fullmraptorOutput;
        internal string docType;
        internal bool olevbaMacro;
        internal bool olevbaAutoExecutable;
        internal bool olevbaSuspiciousKeywords;
        internal bool olevbaIOCs;
        internal bool olevbaHexStrings;
        internal bool olevbaBase64Strings;
        internal bool olevbaDridexStrings;
        internal bool olevbaVbaStrings;
        internal bool mraptorSuspicious;
        internal string mraptorFlags;
        internal bool errorFlag;
        

        public void ScanOLEContent(string fileName)
        {
            OlevbaScan(fileName);
            MraptorScan(fileName);
        }

        private void MraptorScan(string fileName)
        {
            //Close process when execution chain is finished
            using (Process process = new Process())
            {
                //Call the mraptor executable within the users environment variables
                process.StartInfo.FileName = "mraptor";
                string argument = '\"' + fileName + '"';
                process.StartInfo.Arguments = argument;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.RedirectStandardOutput = true;
                process.Start();

                // Synchronously read the standard output of the spawned process. 
                StreamReader reader = process.StandardOutput;
                //Console.WriteLine(reader.ReadToEnd());
                fullmraptorOutput = reader.ReadToEnd();

                process.WaitForExit();
                if (fullmraptorOutput.Contains("can't concat str to bytes"))
                {
                    mraptorSuspicious = true;
                    errorFlag = true;
                }
                else
                {
                    string[] output = fullmraptorOutput.Split(Environment.NewLine.ToCharArray());
                    ParsemraptorOutput(output);
                }
            }
        }

        private void ParsemraptorOutput(string[] mraptorOutput)
        {
            mraptorSuspicious = mraptorOutput[10].Contains("SUSPICIOUS");
            mraptorFlags = mraptorOutput[10].Substring(11, 3);
        }

        private void OlevbaScan(string fileName)
        {
            //Close process when execution chain is finished
            using (Process process = new Process())
            {
                //Call the olevba executable within the users environment variables
                process.StartInfo.FileName = "olevba";
                string argument = "-t " + '\"' + fileName + '"';
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

        private void ParseolevbaOutput(string[] olevbaOutput)
        {
            docType = olevbaOutput[6].Substring(0, 3);
            olevbaMacro = olevbaOutput[6].Substring(4, 1).Contains("M");
            olevbaAutoExecutable = olevbaOutput[6].Substring(5, 1).Contains("A");
            olevbaSuspiciousKeywords = olevbaOutput[6].Substring(6, 1).Contains("S");
            olevbaIOCs = olevbaOutput[6].Substring(7, 1).Contains("I");
            olevbaHexStrings = olevbaOutput[6].Substring(8, 1).Contains("H");
            olevbaBase64Strings = olevbaOutput[6].Substring(9, 1).Contains("B");
            olevbaDridexStrings = olevbaOutput[6].Substring(10, 1).Contains("D");
            olevbaVbaStrings = olevbaOutput[6].Substring(11, 1).Contains("V");
        }
    }
}
