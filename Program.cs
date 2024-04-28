using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using SharpPcap;
using PacketDotNet;

namespace sniffer
{
    internal static class Program
    {
        static void Main(string[] args)
        {
            // Parsing the arguments using CommandLine parser, the argument options are
            // specified in the Parser class. In case of invalid supplied arguments, an
            // error message is called for
            CommandLine.Parser.Default.ParseArguments<Parser>(args)
                .WithParsed(options => HandleInput(options))
                .WithNotParsed(errors => ArgError(errors));
        }

        // There is a unique usecase, which doesnt "sniff" a network, but rather shows 
        // avalable interfaces. Handle input takes care of this usecase. In other cases,
        // HandleInput checks if it can and later calls for a sniffer.
        static void HandleInput(Parser options)
        {
            var interfaces = CaptureDeviceList.Instance;

            // Check for existing intefaces
            if (interfaces.Count < 1)
            {
                Console.Error.WriteLine("No interfaces found.");
                return;
            }

            if (string.IsNullOrEmpty(options.Interface))
            {
                foreach (var inf in interfaces)
                {
                    Console.WriteLine(inf.Name);
                }
                return;
            }

            Sniffer.RunSniffer(options);

        }

        // ArgError outputs error messages
        static void ArgError(IEnumerable<Error> errors)
        {
            Console.Error.WriteLine("Invalid usage.");
            foreach (var error in errors)
            {
                Console.Error.WriteLine(error.ToString());
            }
        }

    }
}
