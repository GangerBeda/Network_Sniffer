using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using CommandLine.Text;
using SharpPcap;
using PacketDotNet;
using PacketDotNet.Ieee80211;
using System.Runtime.CompilerServices;
using System.Net.NetworkInformation;
using System.Net;
using System.Runtime.InteropServices;

namespace sniffer
{
    internal class Sniffer
    {
        // Integers used for tracking the ammount of the tracked packets.
        static int capturedPackets = 0;
        static int maxPackets;

        // RunSniffer is used to initialise capturing of packets on the targeted interface.
        // Most of the code war written according to the sharpcap github tutorials.
        public static void RunSniffer(Parser options)
        {
            maxPackets = options.n;

            var targetInt = CaptureDeviceList.Instance.FirstOrDefault(d => d.Name == options.Interface);
            // checking the existence of the chosen interface
            if (targetInt == null)
            {
                Console.Error.WriteLine("Interface not found.");
                return;
            }

            targetInt.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);
            targetInt.Open(DeviceModes.Promiscuous);

            // Filter is built in the parser class and applied to the targetted interface
            string filter = options.BuildFilter();
            targetInt.Filter = filter;

            targetInt.StartCapture();
            Console.ReadLine();
            targetInt.StopCapture();
            targetInt.Close();
        }

        // The idea is to write out the information about the packet before taking care of the byte offset
        // data output, which will have a dedicated class for it (i think, I havent done it yet).
        static void device_OnPacketArrival(object sender, PacketCapture e)
        {
            capturedPackets++;
            var rawpacket = e.GetPacket();
            var rawtime = rawpacket.Timeval.Date.ToUniversalTime();
            var offset = TimeSpan.FromHours(2);
            var timeWithOffset = TimeZoneInfo.ConvertTime(rawtime, TimeZoneInfo.Local);
            var time = timeWithOffset.ToString("yyyy-MM-dd'T'HH:mm:ss.fffzzz");
            var frameLength = rawpacket.Data.Length;
            var packet = Packet.ParsePacket(rawpacket.LinkLayerType, rawpacket.Data);
            var arpPacket = packet.Extract<ArpPacket>();
            var tcpPacket = packet.Extract<TcpPacket>();
            var udpPacket = packet.Extract<UdpPacket>();
            var icmpv4Packet = packet.Extract<IcmpV4Packet>();
            var icmpv6Packet = packet.Extract<IcmpV6Packet>();
            var igmpPacket = packet.Extract<IgmpPacket>();

            // In this part, first, I check for the packet type, extract the information
            // accordingly and output it.
            if (arpPacket != null)
            {
                System.Net.IPAddress srcIp = arpPacket.SenderProtocolAddress;
                System.Net.IPAddress dstIp = arpPacket.TargetProtocolAddress;
                var srcMac = Printer.FormatMacAddress(arpPacket.SenderHardwareAddress);
                var dstMac = Printer.FormatMacAddress(arpPacket.TargetHardwareAddress);

                Printer.PrintNoPort(time, frameLength, srcMac, dstMac, srcIp, dstIp);

            }
            else if (packet.Extract<NdpPacket>() != null)
            {
                var srcMac = "00:00:00:00:00:00";
                var dstMac = "00:00:00:00:00:00";
                if (packet.Extract<EthernetPacket>() != null)
                {
                    var ethernetPacket = (EthernetPacket)packet;
                    srcMac = Printer.FormatMacAddress(ethernetPacket.SourceHardwareAddress);
                    dstMac = Printer.FormatMacAddress(ethernetPacket.DestinationHardwareAddress);
                }
                var ipPacket = (IPv6Packet)packet.PayloadPacket;
                var srcIp = ipPacket.SourceAddress;
                var dstIp = ipPacket.DestinationAddress;

                Printer.PrintNoPort(time, frameLength, srcMac, dstMac, srcIp, dstIp);
            }
            else if (igmpPacket != null)
            {
                var ipPacket = (IPPacket)igmpPacket.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;

                var srcMac = "00:00:00:00:00:00";
                var dstMac = "00:00:00:00:00:00";
                if (packet.Extract<EthernetPacket>() != null)
                {
                    var ethernetPacket = (EthernetPacket)packet;
                    srcMac = Printer.FormatMacAddress(ethernetPacket.SourceHardwareAddress);
                    dstMac = Printer.FormatMacAddress(ethernetPacket.DestinationHardwareAddress);
                }

                Printer.PrintNoPort(time, frameLength, srcMac, dstMac, srcIp, dstIp);
            }
            else if (icmpv4Packet != null)
            {
                var ipPacket = (IPPacket)icmpv4Packet.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;

                var srcMac = "00:00:00:00:00:00";
                var dstMac = "00:00:00:00:00:00";
                if (packet.Extract<EthernetPacket>() != null)
                {
                    var ethernetPacket = (EthernetPacket)packet;
                    srcMac = Printer.FormatMacAddress(ethernetPacket.SourceHardwareAddress);
                    dstMac = Printer.FormatMacAddress(ethernetPacket.DestinationHardwareAddress);
                }

                Printer.PrintNoPort(time, frameLength, srcMac, dstMac, srcIp, dstIp);
            }
            else if (icmpv6Packet != null)
            {
                var ipPacket = (IPPacket)icmpv6Packet.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;

                var srcMac = "00:00:00:00:00:00";
                var dstMac = "00:00:00:00:00:00";
                if (packet.Extract<EthernetPacket>() != null)
                {
                    var ethernetPacket = (EthernetPacket)packet;
                    srcMac = Printer.FormatMacAddress(ethernetPacket.SourceHardwareAddress);
                    dstMac = Printer.FormatMacAddress(ethernetPacket.DestinationHardwareAddress);
                }

                Printer.PrintNoPort(time, frameLength, srcMac, dstMac, srcIp, dstIp);
            }
            else if (tcpPacket != null)
            {
                var tcpPacket2 = packet.Extract<TcpPacket>();
                var ipPacket = (IPPacket)tcpPacket2.ParentPacket;
                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = tcpPacket2.SourcePort;
                int dstPort = tcpPacket2.DestinationPort;

                var srcMac = "00:00:00:00:00:00";
                var dstMac = "00:00:00:00:00:00";
                if (packet.Extract<EthernetPacket>() != null)
                {
                    var ethernetPacket = (EthernetPacket)packet;
                    srcMac = Printer.FormatMacAddress(ethernetPacket.SourceHardwareAddress);
                    dstMac = Printer.FormatMacAddress(ethernetPacket.DestinationHardwareAddress);
                }

                Printer.PrintTcpUdp(time, frameLength, srcMac, dstMac, srcIp, dstIp, srcPort, dstPort);
            }
            else if (udpPacket != null)
            {
                var ipPacket = (IPPacket)udpPacket.ParentPacket;

                var srcMac = "00:00:00:00:00:00";
                var dstMac = "00:00:00:00:00:00";
                if (packet.Extract<EthernetPacket>()!=null)
                {
                    var ethernetPacket = (EthernetPacket)packet;
                    srcMac = Printer.FormatMacAddress(ethernetPacket.SourceHardwareAddress);
                    dstMac = Printer.FormatMacAddress(ethernetPacket.DestinationHardwareAddress);
                }

                System.Net.IPAddress srcIp = ipPacket.SourceAddress;
                System.Net.IPAddress dstIp = ipPacket.DestinationAddress;
                int srcPort = udpPacket.SourcePort;
                int dstPort = udpPacket.DestinationPort;

                Printer.PrintTcpUdp(time, frameLength, srcMac, dstMac, srcIp, dstIp, srcPort, dstPort);
            }
            else
            {
                // In case the packet is an not recognised, the frame length is the only outputted information.
                Console.WriteLine($"timestamp: {time}");
                Console.WriteLine($"frame length: {frameLength} bytes");
                Console.WriteLine("Unrecognised packet type.");
            }

            Printer.DataOutput(e.GetPacket().Data);
            
            if(capturedPackets >= maxPackets)
            {
                var targetInt = (ICaptureDevice)sender;
                targetInt.StopCapture();
                targetInt.Close();
                Environment.Exit(0);
            }
        }
    }
}