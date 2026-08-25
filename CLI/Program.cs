using System.Diagnostics;
using System.Reflection;

namespace ADSecurityAuditCLI
{
    class Program
    {
        public static string RuntimeExtractPath { get; private set; } = string.Empty;

        static async Task<int> Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("=========================================================================");
            Console.WriteLine("  Active Directory Security Audit Framework v2.2.0 (Read-Only)");
            Console.WriteLine("=========================================================================");
            Console.ResetColor();

            try
            {
                UnpackEmbeddedResources();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[CRITICAL ERROR] Failed unpacking embedded audit resources: {ex.Message}");
                Console.ResetColor();
                return 1;
            }

            AppDomain.CurrentDomain.ProcessExit += (s, e) => CleanupTempResources();

            string pwshExecutable = FindPowerShellExecutable();
            if (string.IsNullOrEmpty(pwshExecutable))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[ERROR] PowerShell was not found on this system.");
                if (OperatingSystem.IsWindows())
                {
                    Console.WriteLine("[INFO] Install PowerShell 7 from https://aka.ms/powershell");
                    Console.WriteLine("       Windows PowerShell 5.1 is used automatically when PowerShell 7 is not installed.");
                }
                else
                {
                    Console.WriteLine("[INFO] Install PowerShell 7: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux");
                }
                Console.ResetColor();
                return 1;
            }

            string orchestratorScript = Path.Combine(RuntimeExtractPath, "Invoke-ADSecurityAudit.ps1");
            string pwshArgs = $"-NoProfile -File \"{orchestratorScript}\" " + string.Join(" ", args);

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[*] PowerShell detected: {pwshExecutable}");
            Console.WriteLine($"[*] Executing audit orchestrator...");
            Console.ResetColor();

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = pwshExecutable,
                    Arguments = pwshArgs,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true,
                    WorkingDirectory = RuntimeExtractPath
                };

                using (Process process = new Process { StartInfo = psi })
                {
                    process.OutputDataReceived += (s, e) =>
                    {
                        if (!string.IsNullOrEmpty(e.Data))
                        {
                            Console.WriteLine(e.Data);
                        }
                    };
                    process.ErrorDataReceived += (s, e) =>
                    {
                        if (!string.IsNullOrEmpty(e.Data))
                        {
                            Console.ForegroundColor = ConsoleColor.Yellow;
                            Console.WriteLine($"[STDERR] {e.Data}");
                            Console.ResetColor();
                        }
                    };

                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();
                    await process.WaitForExitAsync();

                    return process.ExitCode;
                }
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[CRITICAL EXCEPTION] {ex.Message}");
                Console.ResetColor();
                return 1;
            }
            finally
            {
                CleanupTempResources();
            }
        }

        private static string FindPowerShellExecutable()
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
            }

            return null;
        }

        private static void UnpackEmbeddedResources()
        {
            string tempDir = Path.Combine(Path.GetTempPath(), "AD-Security-Audit-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            RuntimeExtractPath = tempDir;

            Assembly assembly = Assembly.GetExecutingAssembly();
            foreach (string resName in assembly.GetManifestResourceNames())
            {
                string relPath = ConvertResourceNameToPath(resName);
                if (string.IsNullOrEmpty(relPath)) continue;

                string destPath = Path.Combine(tempDir, relPath);
                string? dir = Path.GetDirectoryName(destPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }

                using Stream? stream = assembly.GetManifestResourceStream(resName);
                if (stream == null)
                {
                    continue;
                }

                using FileStream fs = new FileStream(destPath, FileMode.Create, FileAccess.Write);
                stream.CopyTo(fs);
            }
        }

        private static string ConvertResourceNameToPath(string resourceName)
        {
            string prefix = "ADSecurityAuditCLI.Resources.";
            if (!resourceName.StartsWith(prefix)) return string.Empty;

            string pathWithoutPrefix = resourceName.Substring(prefix.Length);

            if (pathWithoutPrefix.StartsWith("Modules."))
            {
                return Path.Combine("Modules", pathWithoutPrefix.Substring("Modules.".Length));
            }
            if (pathWithoutPrefix.StartsWith("Config."))
            {
                return Path.Combine("Config", pathWithoutPrefix.Substring("Config.".Length));
            }

            return pathWithoutPrefix;
        }

        private static void CleanupTempResources()
        {
            try
            {
                if (!string.IsNullOrEmpty(RuntimeExtractPath) && Directory.Exists(RuntimeExtractPath))
                {
                    Directory.Delete(RuntimeExtractPath, true);
                }
            }
            catch { }
        }
    }
}
