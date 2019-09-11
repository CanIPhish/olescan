using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;

namespace olescan
{
    class Options
    {
        // Omitting long name, defaults to name of property, ie "--verbose"
        [Option('v', "verbose", Default = false, HelpText = "output the verbose analysis to console")]
        public bool verbose { get; set; }

        [Option('o', "output", Default = "", HelpText = "output scanning results into a comma delimited file (e.g. -o \"C:\\results.csv\")")]
        public string output { get; set; }

        [Option('b', "batch", Default = false, HelpText = "input a pipe delimited list in-place of <filename> for scanning automation")]
        public bool batch { get; set; }

        [Option('h', "help", Default = false, HelpText = "show help message and exit")]
        public bool help { get; set; }
    }
}
