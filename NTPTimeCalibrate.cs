using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

public class NtpTimeSync
{
    // 用于设置系统时间的Win32 API结构体和函数
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEMTIME
    {
        public short wYear;
        public short wMonth;
        public short wDayOfWeek;
        public short wDay;
        public short wHour;
        public short wMinute;
        public short wSecond;
        public short wMilliseconds;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetSystemTime(ref SYSTEMTIME st);

    public async static Task NTPMain()
    {
        const string ntpServer = "ntp1.aliyun.com";
        try
        {
            // 1. 解析NTP服务器IP
            var addresses = Dns.GetHostEntry(ntpServer).AddressList;
            var ipEndPoint = new IPEndPoint(addresses[0], 123);
            Console.WriteLine($"解析IP: {addresses[0]}");
            Console.WriteLine($"本地时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}");
            DateTime ntpUtcTime = GetNtpTime(ipEndPoint);
            Console.WriteLine($"服务器时间: {ntpUtcTime.ToLocalTime():yyyy-MM-dd HH:mm:ss.fff} (UTC: {ntpUtcTime:yyyy-MM-dd HH:mm:ss.fff})");

            SYSTEMTIME systemTimeUtc = new SYSTEMTIME
            {
                wYear = (short)ntpUtcTime.Year,
                wMonth = (short)ntpUtcTime.Month,
                wDay = (short)ntpUtcTime.Day,
                wDayOfWeek = (short)ntpUtcTime.DayOfWeek,
                wHour = (short)ntpUtcTime.Hour,         // 使用UTC小时
                wMinute = (short)ntpUtcTime.Minute,   // 使用UTC分钟
                wSecond = (short)ntpUtcTime.Second,   // 使用UTC秒
                wMilliseconds = (short)ntpUtcTime.Millisecond
            };

            // 5. 调用API设置系统时间
            if (SetSystemTime(ref systemTimeUtc))
            {
                // 6. 获取设置成功后的新本地时间并输出
                Console.WriteLine($"本地新时间: {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}");
                Console.WriteLine("系统时间同步成功！");
            }
            else
            {
                int errorCode = Marshal.GetLastWin32Error();
                Console.WriteLine($"错误: 设置系统时间失败。Win32错误码: {errorCode}。");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"发生异常: {ex.Message}");
        }
    }

    private static DateTime GetNtpTime(IPEndPoint ipEndPoint)
    {
        var ntpData = new byte[48];
        ntpData[0] = 0x1B;

        using (var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
        {
            socket.Connect(ipEndPoint);
            socket.ReceiveTimeout = 3000;
            socket.Send(ntpData);
            socket.Receive(ntpData);
            socket.Close();
        }

        const byte serverReplyTime = 40;
        ulong intPart = BitConverter.ToUInt32(ntpData, serverReplyTime);
        ulong fractPart = BitConverter.ToUInt32(ntpData, serverReplyTime + 4);

        intPart = SwapEndianness(intPart);
        fractPart = SwapEndianness(fractPart);

        var milliseconds = (intPart * 1000) + ((fractPart * 1000) / 0x100000000L);

        var networkDateTime = (new DateTime(1900, 1, 1, 0, 0, 0, DateTimeKind.Utc)).AddMilliseconds((long)milliseconds);

        return networkDateTime;
    }

    static uint SwapEndianness(ulong x)
    {
        return (uint)(((x & 0x000000ff) << 24) +
                       ((x & 0x0000ff00) << 8) +
                       ((x & 0x00ff0000) >> 8) +
                       ((x & 0xff000000) >> 24));
    }
}