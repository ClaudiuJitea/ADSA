using Avalonia;
using System;

namespace ADSecurityAuditGUI;

internal static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        try
        {
            BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("Failed to start the AD Security Audit GUI.");
            Console.Error.WriteLine(ex);
            Console.Error.WriteLine();
            Console.Error.WriteLine("This GUI needs a desktop session (Windows, X11, or Wayland).");
            Environment.ExitCode = 1;
        }
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
