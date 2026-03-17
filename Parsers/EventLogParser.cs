using MeasuredBootParser.Models;

namespace MeasuredBootParser.Parsers
{
    public static class EventLogParser
    {
        // Signature bytes for TCG2 Spec ID Event
        private static readonly byte[] Tcg2Signature =
            System.Text.Encoding.ASCII.GetBytes("Spec ID Event03\0");

        public static TcgEventLog Parse(string filePath)
        {
            var data = File.ReadAllBytes(filePath);
            return Parse(data, filePath);
        }

        public static TcgEventLog Parse(byte[] data, string sourceName)
        {
            using var ms = new MemoryStream(data);
            using var br = new BinaryReader(ms);

            var log = new TcgEventLog
            {
                FilePath = sourceName,
                FileSize = data.Length
            };

            // Peek at the first event to determine format
            // First event is always a TCG 1.2-style header
            if (data.Length < 32)
                throw new InvalidDataException("File too small to be a valid TCG Event Log.");

            bool isCryptoAgile = DetectFormat(data);
            log.IsCryptoAgile = isCryptoAgile;

            if (isCryptoAgile)
            {
                var parser = new Tcg20Parser();
                parser.Parse(br, log);
            }
            else
            {
                var parser = new Tcg12Parser();
                parser.Parse(br, log);
            }

            return log;
        }

        private static bool DetectFormat(byte[] data)
        {
            // The first event is TCG1.2-style EV_NO_ACTION (type=3).
            // If its EventData starts with "Spec ID Event03\0", it's TCG 2.0.
            try
            {
                using var ms = new MemoryStream(data);
                using var br = new BinaryReader(ms);

                uint pcrIndex = br.ReadUInt32();  // should be 0
                uint eventType = br.ReadUInt32();  // should be 3 (EV_NO_ACTION)
                br.ReadBytes(20);                    // SHA1 digest (zeroed in 2.0 header)
                uint eventSize = br.ReadUInt32();

                if (eventType == 0x00000003 && eventSize >= 16)
                {
                    byte[] eventData = br.ReadBytes((int)eventSize);
                    // Check for "Spec ID Event03\0"
                    if (eventData.Length >= 16)
                    {
                        var sig = new byte[16];
                        Array.Copy(eventData, sig, 16);
                        if (System.Collections.StructuralComparisons.StructuralEqualityComparer
                                .Equals(sig, Tcg2Signature))
                            return true;
                    }
                }
            }
            catch { /* fall through */ }

            return false;
        }
    }
}