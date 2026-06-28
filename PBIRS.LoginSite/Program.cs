using System;
using PBIRS.Common;
using Serilog;

namespace PBIRS.LoginSite
{
    class Program
    {
        static void Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration().WriteTo.Console().CreateLogger();
            Log.Information("PBIRS.LoginSite starting");

            Console.WriteLine(Class1.Hello());
        }
    }
}
