using System;
using Serilog;

namespace PBIRS.SecurityExtension
{
    public class SecurityExtension
    {
        public static void Initialize()
        {
            Log.Logger = new LoggerConfiguration()
                .WriteTo.Console()
                .CreateLogger();

            Log.Information("PBIRS.SecurityExtension initialized");
        }
    }
}
