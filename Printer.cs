using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using System.Threading.Tasks;

namespace sniffer
{
    // Printer takes care of most of the program output cases.
    public class Printer
    {
        public static void DataOutput(byte[] data)
        {
            const int bytesPerLine = 16;            
            Console.WriteLine();

            for (int i = 0; i < data.Length; i += bytesPerLine)
            {
                var lineData = data.Skip(i).Take(bytesPerLine);
                var byteOffset = i.ToString("X4");

                Console.Write($"{byteOffset}: ");

                foreach (var b in lineData)
                {
                    Console.Write($"{b:X2} ");
                }

                Console.Write("".PadRight((bytesPerLine - lineData.Count()) * 3));
                Console.Write("  ");
                foreach (var b in lineData)
                {
                    Console.Write(b < 32 || b > 126 ? "." : Convert.ToChar(b));
                }

                Console.WriteLine();
            }
            Console.WriteLine();
        }

        // A method for formatting the MacAddresses to match the reference output.
        public static string FormatMacAddress(PhysicalAddress address)
        {
            byte[] bytes = address.GetAddressBytes();
            return string.Join(":", bytes.Select(b => b.ToString("X2")));
        }

        // PrintTcpUdp prints out the data as shown in the provided reference output
        public static void PrintTcpUdp(string time, int frameLength, string srcMac, string dstMac, IPAddress srcIp, IPAddress dstIp, int srcPort, int dstPort)
        {
            Console.WriteLine($"timestamp: {time}");
            Console.WriteLine($"frame length: {frameLength} bytes");
            Console.WriteLine($"src MAC: {srcMac}");
            Console.WriteLine($"dst MAC: {dstMac}");
            Console.WriteLine($"src IP: {srcIp}");
            Console.WriteLine($"dst IP: {dstIp}");
            Console.WriteLine($"src port: {srcPort}");
            Console.WriteLine($"dst port: {dstPort}");
        }

        // In case of a packet not holding port numbers, this method is called
        public static void PrintNoPort(string time, int frameLength, string srcMac, string dstMac, IPAddress srcIp, IPAddress dstIp)
        {
            Console.WriteLine($"timestamp: {time}");
            Console.WriteLine($"frame length: {frameLength} bytes");
            Console.WriteLine($"src MAC: {srcMac}");
            Console.WriteLine($"dst MAC: {dstMac}");
            Console.WriteLine($"src IP: {srcIp}");
            Console.WriteLine($"dst IP: {dstIp}");
        }
    }
}
