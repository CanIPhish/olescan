using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace olescan
{
    class SuspicionScoring
    {
        private float olvevbaAutoExecutableScore;
        private float olevbaSuspiciousKeywordsScore;
        private float olvevbaIOCsScore;
        private float olevbaHexStringsScore;
        private float olevbaBase64StringsScore;
        private float olevbaDridexStringsScore;
        private float olevbaVbaStringsScore;
        private float mraptorSuspiciousScore;

        public float SuspicionAnalysis()
        {
            return 0;
        }
    }
}
