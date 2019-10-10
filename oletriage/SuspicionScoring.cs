using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace olescan
{
    class SuspicionScoring
    {
        private double olevbaAutoExecutableScore = 0;
        private double olevbaSuspiciousKeywordsScore = 0;
        private double olevbaIOCsScore = 0;
        //private double olevbaHexStringsScore = 0;
        //private double olevbaBase64StringsScore = 0;
        //private double olevbaDridexStringsScore = 0;
        //private double olevbaVbaStringsScore = 0;
        private double olevbaEncodedStringScore = 0;
        private double mraptorSuspiciousScore = 0;

        public double SuspicionAnalysis(ContentAnalysis cAnalysis)
        {
            double suspicionScore;

            if (cAnalysis.olevbaAutoExecutable) { olevbaAutoExecutableScore = 0.1; }
            if (cAnalysis.olevbaSuspiciousKeywords) { olevbaSuspiciousKeywordsScore = 0.25; }
            if (cAnalysis.olevbaIOCs) { olevbaIOCsScore = 0.25; }
            if (cAnalysis.olevbaHexStrings || cAnalysis.olevbaBase64Strings || cAnalysis.olevbaDridexStrings || cAnalysis.olevbaDridexStrings || cAnalysis.olevbaVbaStrings)
            {
                olevbaEncodedStringScore = 0.15;
            }
            //if (cAnalysis.olevbaBase64Strings) { olevbaBase64StringsScore = 0.15; }
            //if (cAnalysis.olevbaDridexStrings) { olevbaDridexStringsScore = 0.15; }
            //if (cAnalysis.olevbaVbaStrings) { olevbaVbaStringsScore = 0.15; }
            if (cAnalysis.mraptorSuspicious) { mraptorSuspiciousScore = 0.4; }

            //suspicionScore = olevbaAutoExecutableScore + olevbaSuspiciousKeywordsScore + olevbaIOCsScore + olevbaHexStringsScore 
            //    + olevbaBase64StringsScore + olevbaDridexStringsScore + olevbaVbaStringsScore + mraptorSuspiciousScore;
            suspicionScore = olevbaAutoExecutableScore + olevbaSuspiciousKeywordsScore + olevbaIOCsScore + olevbaEncodedStringScore + mraptorSuspiciousScore;

            if (suspicionScore > 1 || cAnalysis.errorFlag) { suspicionScore = 1; }

            return suspicionScore;
    }
    }
}
