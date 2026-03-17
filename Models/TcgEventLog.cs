using System.Collections.Generic;

namespace MeasuredBootParser.Models
{
    public class TcgEventLog
    {
        public bool IsCryptoAgile { get; set; }   // true = TCG 2.0, false = TCG 1.2
        public SpecIdEvent? SpecId { get; set; }
        public List<TcgEvent> Events { get; set; } = [];

        // PCR bank indexed by [algorithmId][pcrIndex] = digest bytes
        public Dictionary<ushort, Dictionary<uint, byte[]>> PcrBanks { get; set; } = [];

        public string FilePath { get; set; } = "";
        public long FileSize { get; set; }
    }
}