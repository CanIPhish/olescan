using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Diagnostics;

namespace olescan
{
    class ContentDetection
    {
        private bool oleFormat;
        private string fileType;
        private bool encrypted;
        private bool vbaMacro;
        private bool flashObjects;
        private string fullOutput;

        //Core Method for detection of document contents through use of oleid
        public bool DetectOLEContent(string fileName)
        {
            //Close process when execution chain is finished
            using (Process process = new Process())
            {
                //Call the oleid executable within the users environment variables with a parameter of file location and name
                process.StartInfo.FileName = "oleid";
                process.StartInfo.Arguments = '\"' + fileName + '"';
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.Start();

                // Synchronously read the standard output of the spawned process. 
                StreamReader reader = process.StandardOutput;
                fullOutput = reader.ReadToEnd();
                //Console.WriteLine(fullOutput);
                string[] output = fullOutput.Split(Environment.NewLine.ToCharArray());

                process.WaitForExit();
                ParseoleidOutput(output);
                return oleFormat;
            }
        }

        private void ParseoleidOutput(string[] oleidOutput)
        {
            oleFormat = oleidOutput[12].Contains("True");
            if(oleFormat)
            {
                fileType = oleidOutput[16].Substring(oleidOutput[16].IndexOf("'")).Replace("'", "");
                encrypted = oleidOutput[18].Contains("True");
                vbaMacro = oleidOutput[22].Contains("True");
                flashObjects = !oleidOutput[32].Contains("0");
            }
            //foreach (string contentString in oleidOutput)
            //{
            //    Console.WriteLine(contentString);
            //}
        }

    }
}
