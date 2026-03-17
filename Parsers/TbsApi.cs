using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace MeasuredBootParser.Parsers
{
    /// <summary>
    /// P/Invoke wrapper for Windows TBS (TPM Base Services) API.
    /// Requires administrator privileges.
    /// </summary>
    public static class TbsApi
    {
        // TBS_TCGLOG types
        private const uint TBS_TCGLOG_SRTM_CURRENT = 0;

        private const uint TBS_SUCCESS = 0;
        private const uint TPM2_CC_PCR_READ = 0x0000017E;

        // TBS_COMMAND_PRIORITY
        private const uint TBS_COMMAND_PRIORITY_NORMAL = 200;

        [StructLayout(LayoutKind.Sequential)]
        private struct TBS_CONTEXT_PARAMS2
        {
            public uint version;       // TBS_CONTEXT_VERSION_TWO = 2
            public uint requestRaw;    // union { asUINT32; struct { requestRaw:1; includeTpm12:1; includeTpm20:1 } }
        }

        [DllImport("tbs.dll", EntryPoint = "Tbsi_Context_Create", CallingConvention = CallingConvention.Winapi)]
        private static extern uint Tbsi_Context_Create(
            ref TBS_CONTEXT_PARAMS2 pContextParams,
            out IntPtr phContext);

        [DllImport("tbs.dll", EntryPoint = "Tbsip_Submit_Command", CallingConvention = CallingConvention.Winapi)]
        private static extern uint Tbsip_Submit_Command(
            IntPtr hContext,
            uint locality,
            uint priority,
            byte[] pabCommand,
            uint cbCommand,
            byte[] pabResult,
            ref uint pcbResult);

        [DllImport("tbs.dll", EntryPoint = "Tbsip_Context_Close", CallingConvention = CallingConvention.Winapi)]
        private static extern uint Tbsip_Context_Close(IntPtr hContext);

        [DllImport("tbs.dll", EntryPoint = "Tbsi_Get_TCG_Log_Ex", CallingConvention = CallingConvention.Winapi)]
        private static extern uint Tbsi_Get_TCG_Log_Ex(
            uint logType,
            byte[]? pbOutput,
            ref uint pcbOutput);

        /// <summary>
        /// Reads the current-boot SRTM TCG event log directly from the TPM via the TBS API.
        /// </summary>
        public static byte[] GetTcgLog()
        {
            uint size = 0;
            uint result = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, null, ref size);

            if (size == 0)
                throw new InvalidOperationException(
                    $"Tbsi_Get_TCG_Log_Ex failed to report buffer size. HRESULT=0x{result:X8}. " +
                    "Make sure you are running as Administrator.");

            byte[] buffer = new byte[size];
            result = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, buffer, ref size);

            if (result != TBS_SUCCESS)
                throw new InvalidOperationException(
                    $"Tbsi_Get_TCG_Log_Ex failed. HRESULT=0x{result:X8}. " +
                    "Make sure you are running as Administrator.");

            if (size < (uint)buffer.Length)
                Array.Resize(ref buffer, (int)size);

            return buffer;
        }

        /// <summary>
        /// Reads actual PCR values from the TPM via TPM2_CC_PCR_Read.
        /// Returns Dictionary[algId] -> Dictionary[pcrIndex] -> digest bytes.
        /// </summary>
        public static Dictionary<ushort, Dictionary<uint, byte[]>> ReadPcrValues(
            IEnumerable<ushort> algIds, IEnumerable<uint> pcrIndices)
        {
            var result = new Dictionary<ushort, Dictionary<uint, byte[]>>();

            // Open TBS context (TPM 2.0)
            var ctxParams = new TBS_CONTEXT_PARAMS2
            {
                version = 2,
                requestRaw = 0x04  // includeTpm20 = bit 2
            };
            uint hr = Tbsi_Context_Create(ref ctxParams, out IntPtr hContext);
            if (hr != TBS_SUCCESS)
                throw new InvalidOperationException(
                    $"Tbsi_Context_Create failed. HRESULT=0x{hr:X8}");

            try
            {
                foreach (ushort algId in algIds)
                {
                    int digestSize = GetDigestSize(algId);
                    if (digestSize == 0) continue;

                    var bank = new Dictionary<uint, byte[]>();
                    result[algId] = bank;

                    foreach (uint pcrIdx in pcrIndices)
                    {
                        byte[]? digest = ReadSinglePcr(hContext, algId, pcrIdx, digestSize);
                        if (digest != null)
                            bank[pcrIdx] = digest;
                    }
                }
            }
            finally
            {
                Tbsip_Context_Close(hContext);
            }

            return result;
        }

        private static byte[]? ReadSinglePcr(IntPtr hContext, ushort algId, uint pcrIdx, int digestSize)
        {
            // Build TPM2_PCR_Read command
            // Header: tag(2) + size(4) + commandCode(4) = 10 bytes
            // pcrSelectionIn: count(4) + hash(2) + sizeOfSelect(1) + pcrSelect[](3) = 10 bytes
            // Total = 20 bytes
            byte[] cmd = new byte[20];
            int pos = 0;

            // Tag: TPM_ST_NO_SESSIONS = 0x8001
            WriteBE16(cmd, ref pos, 0x8001);
            // Command size
            WriteBE32(cmd, ref pos, 20);
            // Command code: TPM2_CC_PCR_Read
            WriteBE32(cmd, ref pos, TPM2_CC_PCR_READ);

            // pcrSelectionIn.count = 1
            WriteBE32(cmd, ref pos, 1);
            // pcrSelectionIn[0].hash = algId
            WriteBE16(cmd, ref pos, algId);
            // pcrSelectionIn[0].sizeOfSelect = 3
            cmd[pos++] = 3;
            // pcrSelectionIn[0].pcrSelect = bit mask for pcrIdx
            cmd[pos] = 0; cmd[pos + 1] = 0; cmd[pos + 2] = 0;
            int byteIdx = (int)(pcrIdx / 8);
            int bitIdx = (int)(pcrIdx % 8);
            if (byteIdx < 3)
                cmd[pos + byteIdx] = (byte)(1 << bitIdx);
            pos += 3;

            // Submit command
            byte[] resp = new byte[256];
            uint respSize = (uint)resp.Length;
            uint hr = Tbsip_Submit_Command(hContext, 0, TBS_COMMAND_PRIORITY_NORMAL,
                cmd, (uint)cmd.Length, resp, ref respSize);

            if (hr != TBS_SUCCESS || respSize < 10)
                return null;

            // Parse response
            int rpos = 0;
            ushort rTag = ReadBE16(resp, ref rpos);
            uint rSize = ReadBE32(resp, ref rpos);
            uint rCode = ReadBE32(resp, ref rpos);

            if (rCode != 0) return null; // TPM error

            // pcrUpdateCounter(4)
            uint updateCounter = ReadBE32(resp, ref rpos);
            // pcrSelectionOut.count(4)
            uint selCount = ReadBE32(resp, ref rpos);
            // skip pcrSelectionOut entries
            for (uint i = 0; i < selCount; i++)
            {
                rpos += 2; // hash
                byte sizeOfSel = resp[rpos++];
                rpos += sizeOfSel;
            }
            // pcrValues: TPML_DIGEST -> count(4) + digest[]
            uint digestCount = ReadBE32(resp, ref rpos);
            if (digestCount == 0) return null;

            // First digest: size(2) + data
            ushort dSize = ReadBE16(resp, ref rpos);
            if (rpos + dSize > respSize) return null;

            byte[] digest = new byte[dSize];
            Array.Copy(resp, rpos, digest, 0, dSize);
            return digest;
        }

        private static int GetDigestSize(ushort algId) => algId switch
        {
            0x0004 => 20,   // SHA1
            0x000B => 32,   // SHA256
            0x000C => 48,   // SHA384
            0x000D => 64,   // SHA512
            0x0012 => 32,   // SM3_256
            _ => 0
        };

        private static void WriteBE16(byte[] buf, ref int pos, ushort val)
        {
            buf[pos++] = (byte)(val >> 8);
            buf[pos++] = (byte)(val);
        }

        private static void WriteBE32(byte[] buf, ref int pos, uint val)
        {
            buf[pos++] = (byte)(val >> 24);
            buf[pos++] = (byte)(val >> 16);
            buf[pos++] = (byte)(val >> 8);
            buf[pos++] = (byte)(val);
        }

        private static ushort ReadBE16(byte[] buf, ref int pos)
        {
            ushort v = (ushort)((buf[pos] << 8) | buf[pos + 1]);
            pos += 2;
            return v;
        }

        private static uint ReadBE32(byte[] buf, ref int pos)
        {
            uint v = ((uint)buf[pos] << 24) | ((uint)buf[pos + 1] << 16) |
                     ((uint)buf[pos + 2] << 8) | buf[pos + 3];
            pos += 4;
            return v;
        }
    }
}

