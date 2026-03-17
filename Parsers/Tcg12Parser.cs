using System;
using System.IO;
using System.Collections.Generic;
using MeasuredBootParser.Models;

namespace MeasuredBootParser.Parsers
{
    public class Tcg12Parser
    {
        public void Parse(BinaryReader br, TcgEventLog log)
        {
            log.IsCryptoAgile = false;



            int index = 0;
            while (br.BaseStream.Position < br.BaseStream.Length - 8)
            {
                long offset = br.BaseStream.Position;
                TcgEvent evt;

                try
                {
                    evt = ReadEvent12(br, index, offset);
                }
                catch (EndOfStreamException) { break; }

                log.Events.Add(evt);



                index++;
            }
        }

        private TcgEvent ReadEvent12(BinaryReader br, int index, long offset)
        {
            uint pcrIndex = br.ReadUInt32();
            uint eventType = br.ReadUInt32();
            byte[] sha1 = br.ReadBytes(20);
            uint eventSize = br.ReadUInt32();
            byte[] eventData = br.ReadBytes((int)eventSize);

            return new TcgEvent
            {
                Index = index,
                PcrIndex = pcrIndex,
                EventType = eventType,
                FileOffset = offset,
                Digests = [new DigestEntry { AlgorithmId = 0x0004, Digest = sha1 }],
                EventData = eventData,
                EventDataString = TryDecodeEventData(eventType, eventData),
            };
        }



        internal static string? TryDecodeEventData(uint eventType, byte[] data)
        {
            if (data == null || data.Length == 0) return null;
            try
            {
                switch (eventType)
                {
                    case 0x00000005: // EV_ACTION
                    case 0x00000008: // EV_S_CRTM_VERSION
                    case 0x80000007: // EV_EFI_ACTION
                        return CleanString(System.Text.Encoding.Unicode.GetString(data).TrimEnd('\0'));
                    case 0x80000001: // EV_EFI_VARIABLE_DRIVER_CONFIG
                    case 0x80000002: // EV_EFI_VARIABLE_BOOT
                    case 0x800000E0: // EV_EFI_VARIABLE_AUTHORITY
                        return DecodeEfiVariable(data);
                    default:
                        // Try ASCII
                        bool isAscii = true;
                        foreach (var b in data)
                            if (b != 0 && (b < 0x20 || b > 0x7E)) { isAscii = false; break; }
                        if (isAscii)
                            return System.Text.Encoding.ASCII.GetString(data).TrimEnd('\0');
                        return null;
                }
            }
            catch { return null; }
        }

        private static string DecodeEfiVariable(byte[] data)
        {
            if (data.Length < 28) return "<EFI_VARIABLE too short>";
            var guid = new Guid(
                BitConverter.ToUInt32(data, 0),
                BitConverter.ToUInt16(data, 4),
                BitConverter.ToUInt16(data, 6),
                data[8], data[9], data[10], data[11],
                data[12], data[13], data[14], data[15]);
            ulong nameLen = BitConverter.ToUInt64(data, 16);
            ulong dataLen = BitConverter.ToUInt64(data, 24);
            string name = "";
            if (nameLen > 0 && 32 + (long)nameLen * 2 <= data.Length)
                name = System.Text.Encoding.Unicode.GetString(data, 32, (int)nameLen * 2).TrimEnd('\0');
            return $"GUID={guid} Name={name} DataLen={dataLen}";
        }

        static string CleanString(string s)
        {
            var sb = new System.Text.StringBuilder();
            foreach (char c in s)
                if (c >= 0x20 && c < 0xFFFD) sb.Append(c);
            return sb.ToString().Trim();
        }
    }
}