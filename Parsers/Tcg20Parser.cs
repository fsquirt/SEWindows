using System;
using System.IO;
using System.Collections.Generic;
using MeasuredBootParser.Models;

namespace MeasuredBootParser.Parsers
{
    public class Tcg20Parser
    {
        // Populated from SpecIdEvent
        private List<(ushort AlgId, int DigestSize)> _algorithms = [];

        public void Parse(BinaryReader br, TcgEventLog log)
        {
            log.IsCryptoAgile = true;

            // --- Event 0: TCG1.2-style header (SpecIdEvent) ---
            long offset0 = br.BaseStream.Position;
            uint pcrIdx0 = br.ReadUInt32();
            uint evType0 = br.ReadUInt32();
            byte[] sha1_0 = br.ReadBytes(20);
            uint evSize0 = br.ReadUInt32();
            byte[] evData0 = br.ReadBytes((int)evSize0);

            var specId = ParseSpecIdEvent(evData0);
            log.SpecId = specId;
            log.Events.Add(new TcgEvent
            {
                Index = 0,
                PcrIndex = pcrIdx0,
                EventType = evType0,
                FileOffset = offset0,
                Digests = [new DigestEntry { AlgorithmId = 0x0004, Digest = sha1_0 }],
                EventData = evData0,
                EventDataString = FormatSpecIdEvent(specId),
            });

            // The actual final values are NOT stored in the log file.
            // PcrReplayer will compute the replayed values based on strict TCG rules.

            // --- Remaining events: Crypto Agile format ---
            int index = 1;
            while (br.BaseStream.Position < br.BaseStream.Length - 8)
            {
                long offset = br.BaseStream.Position;
                TcgEvent evt;
                try
                {
                    evt = ReadEvent20(br, index, offset);
                }
                catch (EndOfStreamException) { break; }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"  [!] Parse error at offset 0x{offset:X}: {ex.Message}");
                    break;
                }

                log.Events.Add(evt);

                index++;
            }
        }

        private TcgEvent ReadEvent20(BinaryReader br, int index, long offset)
        {
            uint pcrIndex = br.ReadUInt32();
            uint eventType = br.ReadUInt32();

            uint digestCount = br.ReadUInt32();
            var digests = new List<DigestEntry>();

            for (uint i = 0; i < digestCount; i++)
            {
                ushort algId = br.ReadUInt16();
                int size = GetDigestSize(algId);
                byte[] digest = br.ReadBytes(size);
                digests.Add(new DigestEntry { AlgorithmId = algId, Digest = digest });
            }

            uint eventSize = br.ReadUInt32();
            byte[] eventData = br.ReadBytes((int)eventSize);

            return new TcgEvent
            {
                Index = index,
                PcrIndex = pcrIndex,
                EventType = eventType,
                FileOffset = offset,
                Digests = digests,
                EventData = eventData,
                EventDataString = Tcg12Parser.TryDecodeEventData(eventType, eventData),
            };
        }

        private SpecIdEvent ParseSpecIdEvent(byte[] data)
        {
            // Layout: "Spec ID Event03\0" (16) + platformClass(4) + versionMinor(1) + versionMajor(1)
            //         + errata(1) + uintnSize(1) + numberOfAlgorithms(4) + algList + vendorInfoSize(1)
            var specId = new SpecIdEvent { IsTcg20 = true };
            if (data.Length < 24) return specId;

            int pos = 16; // skip signature
            uint platformClass = BitConverter.ToUInt32(data, pos); pos += 4;
            specId.SpecVersionMinor = data[pos++];
            specId.SpecVersionMajor = data[pos++];
            specId.SpecErrata = data[pos++];
            byte uintnSize = data[pos++];
            uint numAlgs = BitConverter.ToUInt32(data, pos); pos += 4;

            for (uint i = 0; i < numAlgs && pos + 4 <= data.Length; i++)
            {
                ushort algId = BitConverter.ToUInt16(data, pos); pos += 2;
                ushort digSize = BitConverter.ToUInt16(data, pos); pos += 2;
                specId.AlgorithmList.Add((algId, digSize));
                _algorithms.Add((algId, digSize));
            }

            return specId;
        }

        private string FormatSpecIdEvent(SpecIdEvent s)
        {
            var algs = string.Join(", ", s.AlgorithmList.ConvertAll(
                a => $"{TcgAlgorithmId.GetName(a.AlgId)}({a.DigestSize * 8}bit)"));
            return $"TCG Spec {s.SpecVersionMajor}.{s.SpecVersionMinor} Errata={s.SpecErrata} Algorithms=[{algs}]";
        }

        private int GetDigestSize(ushort algId)
        {
            foreach (var (id, size) in _algorithms)
                if (id == algId) return size;
            // fallback to known sizes
            if (TcgAlgorithmId.DigestSizes.TryGetValue(algId, out var s)) return s;
            throw new InvalidDataException($"Unknown algorithm ID 0x{algId:X4} with no known digest size.");
        }


    }
}