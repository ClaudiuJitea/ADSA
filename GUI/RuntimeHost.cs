using System.Diagnostics;
using System.Reflection;

namespace ADSecurityAuditGUI;

internal static class RuntimeHost
{
    public static string RuntimeExtractPath { get; private set; } = string.Empty;

    public static void Initialize()
    {
        try
        {
            ExtractEmbeddedAuditResources();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Failed extracting embedded audit resources: {ex.Message}");
        }

        string orchestrator = Path.Combine(RuntimeExtractPath, "Invoke-ADSecurityAudit.ps1");
        if (!File.Exists(orchestrator))
        {
            string? sourceTree = TryFindSourceTree();
            if (!string.IsNullOrEmpty(sourceTree))
            {
                RuntimeExtractPath = sourceTree;
            }
        }
    }

    public static string FindPowerShellCoreExecutable()
    {
        foreach (string path in GetKnownPowerShellPaths())
        {
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
            {
                return path;
            }
        }

        string? fromPath = FindOnPath(OperatingSystem.IsWindows() ? "pwsh.exe" : "pwsh")
            ?? FindOnPath("pwsh");
        if (!string.IsNullOrEmpty(fromPath))
        {
            return fromPath;
        }

        if (OperatingSystem.IsWindows())
        {
            string windowsPowerShell = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe");
            if (File.Exists(windowsPowerShell))
            {
                return windowsPowerShell;
            }
        }

        return string.Empty;
    }

    private static IEnumerable<string> GetKnownPowerShellPaths()
    {
        if (OperatingSystem.IsWindows())
        {
            string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            yield return Path.Combine(programFiles, "PowerShell", "7", "pwsh.exe");
            yield return Path.Combine(programFiles, "PowerShell", "7-preview", "pwsh.exe");
            yield return Path.Combine(programFilesX86, "PowerShell", "7", "pwsh.exe");
            yield return Path.Combine(localAppData, "Microsoft", "powershell", "pwsh.exe");
            yield break;
        }

        yield return "/usr/bin/pwsh";
        yield return "/usr/local/bin/pwsh";
        yield return "/snap/bin/pwsh";
        yield return "/opt/microsoft/powershell/7/pwsh";
    }

    private static string? FindOnPath(string fileName)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo
            {
                FileName = OperatingSystem.IsWindows() ? "where.exe" : "which",
                Arguments = fileName,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using Process? process = Process.Start(psi);
            if (process == null)
            {
                return null;
            }

            string output = process.StandardOutput.ReadToEnd().Trim();
            process.WaitForExit();
            string first = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? string.Empty;
            if (!string.IsNullOrEmpty(first) && File.Exists(first))
            {
                return first;
            }
        }
        catch
        {
            // Ignore PATH lookup failures and continue.
        }

        return null;
    }

    public static void Cleanup()
    {
        try
        {
            if (string.IsNullOrEmpty(RuntimeExtractPath) || !Directory.Exists(RuntimeExtractPath))
            {
                return;
            }

            string tempRoot = Path.Combine(Path.GetTempPath(), "AD-Security-Audit-GUI-");
            if (RuntimeExtractPath.StartsWith(tempRoot, StringComparison.Ordinal))
            {
                Directory.Delete(RuntimeExtractPath, true);
            }
        }
        catch
        {
            // Suppress cleanup exception on process exit.
        }
    }

    private static void ExtractEmbeddedAuditResources()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "AD-Security-Audit-GUI-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        RuntimeExtractPath = tempDir;

        Assembly assembly = Assembly.GetExecutingAssembly();
        foreach (string resourceName in assembly.GetManifestResourceNames())
        {
            string relativePath = ConvertResourceNameToPath(resourceName);
            if (string.IsNullOrEmpty(relativePath))
            {
                continue;
            }

            string destination = Path.Combine(tempDir, relativePath);
            string? directory = Path.GetDirectoryName(destination);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            using Stream? stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null)
            {
                continue;
            }

            using FileStream fileStream = new FileStream(destination, FileMode.Create, FileAccess.Write);
            stream.CopyTo(fileStream);
        }
    }

    private static string ConvertResourceNameToPath(string resourceName)
    {
        const string prefix = "ADSecurityAuditGUI.Resources.";
        if (!resourceName.StartsWith(prefix, StringComparison.Ordinal))
        {
            return string.Empty;
        }

        string pathWithoutPrefix = resourceName.Substring(prefix.Length);

        if (pathWithoutPrefix.StartsWith("Modules.", StringComparison.Ordinal))
        {
            return Path.Combine("Modules", pathWithoutPrefix.Substring("Modules.".Length));
        }

        if (pathWithoutPrefix.StartsWith("Config.", StringComparison.Ordinal))
        {
            return Path.Combine("Config", pathWithoutPrefix.Substring("Config.".Length));
        }

        return pathWithoutPrefix;
    }

    private static string? TryFindSourceTree()
    {
        string? directory = AppContext.BaseDirectory;
        for (int i = 0; i < 8 && !string.IsNullOrEmpty(directory); i++)
        {
            if (File.Exists(Path.Combine(directory, "Invoke-ADSecurityAudit.ps1")))
            {
                return directory;
            }

            directory = Directory.GetParent(directory)?.FullName;
        }

        return null;
    }
}
