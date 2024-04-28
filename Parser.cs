using CommandLine;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace sniffer
{
    public class Parser
    {
        [Option('i', "interface", HelpText = "Prints active interfaces / Specifies sniffed interface", Default = null)]
        public string ?Interface { get; set; }

        [Option('p', HelpText = "Given port must occur in source OR destination part of TCP/UDP headers")]
        public string ?port { get; set; }

        [Option("port-destination", HelpText = "Given port must occur in destination part of TCP/UDP headers")]
        public string ?portDest { get; set; }

        [Option("port-source", HelpText = "Given port must occur in source part of TCP/UDP headers")]
        public string ?portSrc { get; set; }

        [Option('t', "tcp", HelpText = "Capture only TCP packets.")]
        public bool Tcp { get; set; }

        [Option('u', "udp", HelpText = "Capture only UDP packets.")]
        public bool Udp { get; set; }

        [Option("icmp4", HelpText = "Capture only ICMPv4 packets.")]
        public bool Icmp4 { get; set; }

        [Option("icmp6", HelpText = "Capture only ICMPv6 packets.")]
        public bool Icmp6 { get; set; }

        [Option("arp", HelpText = "Capture only ARP packets.")]
        public bool Arp { get; set; }

        [Option("ndp", HelpText = "Capture only NDP packets.")]
        public bool Ndp { get; set; }

        [Option("igmp", HelpText = "Capture only IGMP packets.")]
        public bool Igmp { get; set; }

        [Option("mld", HelpText = "Capture only MLD packets.")]
        public bool Mld { get; set; }

        [Option('n', HelpText = "Count of packets to be captured.")]
        public int n { get; set; }

        public string BuildFilter()
        {
            var filters = new List<string>();

            if (Tcp)
                filters.Add("tcp");

            if (Udp)
                filters.Add("udp");

            if (!string.IsNullOrEmpty(portSrc))
                filters.Add($"src port {portSrc}");

            if (!string.IsNullOrEmpty(portDest))
                filters.Add($"dst port {portDest}");

            if (Icmp4)
                filters.Add("icmp");

            if (Icmp6)
                filters.Add("icmp6");

            if (Arp)
                filters.Add("arp");

            if (Ndp)
                filters.Add("icmp6 and icmp6.type eq 136");

            if (Igmp)
                filters.Add("igmp");

            if (Mld)
                filters.Add("icmp6 and icmp6.type eq 130");

            return string.Join(" and ", filters);
        }
    }
}
