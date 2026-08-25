using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;

namespace ADSecurityAuditGUI;

public sealed class AuditModuleItem : INotifyPropertyChanged
{
    private bool _isSelected = true;

    public string Id { get; set; } = string.Empty;
    public string Number { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (_isSelected == value)
            {
                return;
            }

            _isSelected = value;
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(nameof(IsSelected)));
        }
    }

    public event PropertyChangedEventHandler? PropertyChanged;
}

public partial class MainWindow : Window
{
    public ObservableCollection<AuditModuleItem> Modules { get; } = new();

    private Process? _activeAuditProcess;
    private bool _isExecuting;

    public MainWindow()
    {
        InitializeComponent();
        InitializeDefaultParameters();
        InitializeModuleGrid();
        ApplyPlatformChrome();
    }

    private void ApplyPlatformChrome()
    {
        string platform = OperatingSystem.IsWindows()
            ? "Windows"
            : OperatingSystem.IsMacOS()
                ? "macOS"
                : "Linux";
        TxtSubtitle.Text = $"{platform}  ·  Read-only authorized audit v2.2  ·  PowerShell  ·  LDAP or RSAT";
        Title = "AD Security Audit";
    }

    private void InitializeDefaultParameters()
    {
        TxtDomain.Text = Environment.GetEnvironmentVariable("USERDNSDOMAIN")
            ?? Environment.GetEnvironmentVariable("USERDOMAIN")
            ?? Environment.GetEnvironmentVariable("REALM")
            ?? string.Empty;

        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        string root = OperatingSystem.IsWindows() && !string.IsNullOrWhiteSpace(desktop)
            ? desktop
            : string.IsNullOrWhiteSpace(home) ? desktop : home;

        TxtOutputPath.Text = Path.Combine(root, "AD-Security-Audit-Output");
        TxtInactiveDays.Text = "90";
    }

    private void InitializeModuleGrid()
    {
        Modules.Add(new AuditModuleItem { Id = "DomainForest", Number = "01", Title = "Domain & forest", Description = "Functional levels, MachineAccountQuota, Recycle Bin, and tombstone lifetime." });
        Modules.Add(new AuditModuleItem { Id = "DomainControllers", Number = "02", Title = "Domain controllers", Description = "EOL OS, Print Spooler, DFSR, RODC password policy, placement, and leftover metadata." });
        Modules.Add(new AuditModuleItem { Id = "PrivilegedGroups", Number = "03", Title = "Privileged groups", Description = "Direct and nested Tier 0 membership, inactive members, and SPNs." });
        Modules.Add(new AuditModuleItem { Id = "TierZero", Number = "04", Title = "Tier 0 attack surface", Description = "Ownership, control ACEs, orphaned SIDs, shadow credentials, and nested groups on Tier 0." });
        Modules.Add(new AuditModuleItem { Id = "UsersServiceAccounts", Number = "05", Title = "Users & service accounts", Description = "PasswordNeverExpires, PASSWD_NOTREQD, Kerberoastable accounts, and shadow credentials." });
        Modules.Add(new AuditModuleItem { Id = "ComputersOS", Number = "06", Title = "Computers & EOL OS", Description = "Active systems on Windows 7/8/Server 2008/2012 and password age." });
        Modules.Add(new AuditModuleItem { Id = "PasswordAuth", Number = "07", Title = "Password & auth policy", Description = "Default domain password policy, FGPP, reversible encryption, and lockout." });
        Modules.Add(new AuditModuleItem { Id = "Kerberos", Number = "08", Title = "Kerberos security", Description = "krbtgt password age, AS-REP roasting, AES on DCs, and duplicate SPNs." });
        Modules.Add(new AuditModuleItem { Id = "Delegation", Number = "09", Title = "Kerberos delegation", Description = "Unconstrained, constrained, protocol transition, and RBCD with trustees." });
        Modules.Add(new AuditModuleItem { Id = "GroupPolicy", Number = "10", Title = "Group Policy", Description = "GPP cpassword, SYSVOL secrets, GPO write ACLs, ownership, and broken GPOs." });
        Modules.Add(new AuditModuleItem { Id = "ADAcl", Number = "11", Title = "AD ACL & DCSync", Description = "Domain root ACLs, DCSync rights, GenericAll and WriteDacl on Tier 0." });
        Modules.Add(new AuditModuleItem { Id = "SchemaSecurity", Number = "12", Title = "Schema security", Description = "LAPS confidentiality, schema change control, and forest partition ACLs." });
        Modules.Add(new AuditModuleItem { Id = "Trusts", Number = "13", Title = "Trust relationships", Description = "SID filtering, TGT delegation, RC4, and stale trust passwords." });
        Modules.Add(new AuditModuleItem { Id = "DNS", Number = "14", Title = "DNS security", Description = "AD-integrated DNS zones configured for non-secure dynamic updates." });
        Modules.Add(new AuditModuleItem { Id = "LdapNtlm", Number = "15", Title = "LDAP & NTLM", Description = "Anonymous LDAP, signing, and channel binding." });
        Modules.Add(new AuditModuleItem { Id = "LapsLocalAdmin", Number = "16", Title = "LAPS", Description = "Legacy Microsoft LAPS and Windows LAPS schema deployment." });
        Modules.Add(new AuditModuleItem { Id = "CertificateServices", Number = "17", Title = "Certificate Services", Description = "ESC1–ESC5, ESC7–ESC9, ESC13, template ownership, and HTTP enrollment." });
        Modules.Add(new AuditModuleItem { Id = "HybridIdentity", Number = "18", Title = "Hybrid identity", Description = "Entra Connect, AZUREADSSOACC Seamless SSO, and AD FS farms." });
        Modules.Add(new AuditModuleItem { Id = "ReplicationSites", Number = "19", Title = "Replication & sites", Description = "Empty sites, NTDS settings inventory, and slow site links." });
        Modules.Add(new AuditModuleItem { Id = "BuiltInPrivileges", Number = "20", Title = "Built-in privileges", Description = "Pre-Windows 2000 Compatible Access, trust builders, Cert Publishers." });
        Modules.Add(new AuditModuleItem { Id = "ManagedServiceAccounts", Number = "21", Title = "Managed service accounts", Description = "gMSA inventory and overly broad password-retrieval ACLs." });
        Modules.Add(new AuditModuleItem { Id = "ExchangePrivileges", Number = "22", Title = "Exchange & apps", Description = "Exchange Windows Permissions, Trusted Subsystem, and Organization Management." });
        Modules.Add(new AuditModuleItem { Id = "AttackPaths", Number = "23", Title = "Attack path indicators", Description = "Correlates failed checks into Tier 0 graph edges." });

        ItemsControlModules.ItemsSource = Modules;
    }

    private void BtnSelectAll_Click(object? sender, RoutedEventArgs e)
    {
        foreach (AuditModuleItem module in Modules)
        {
            module.IsSelected = true;
        }
    }

    private void BtnSelectNone_Click(object? sender, RoutedEventArgs e)
    {
        foreach (AuditModuleItem module in Modules)
        {
            module.IsSelected = false;
        }
    }

    private async void BtnRunAll_Click(object? sender, RoutedEventArgs e)
    {
        foreach (AuditModuleItem module in Modules)
        {
            module.IsSelected = true;
        }

        await ExecuteAuditTaskAsync();
    }

    private async void BtnRunSelected_Click(object? sender, RoutedEventArgs e)
    {
        await ExecuteAuditTaskAsync();
    }

    private async void BtnRunSingleModule_Click(object? sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string moduleId })
        {
            return;
        }

        Dictionary<string, bool> previous = Modules.ToDictionary(m => m.Id, m => m.IsSelected);
        foreach (AuditModuleItem module in Modules)
        {
            module.IsSelected = module.Id == moduleId;
        }

        try
        {
            await ExecuteAuditTaskAsync();
        }
        finally
        {
            foreach (AuditModuleItem module in Modules)
            {
                if (previous.TryGetValue(module.Id, out bool selected))
                {
                    module.IsSelected = selected;
                }
            }
        }
    }

    private async Task ExecuteAuditTaskAsync()
    {
        if (_isExecuting)
        {
            return;
        }

        string runtimePath = RuntimeHost.RuntimeExtractPath;
        string orchestratorScript = Path.Combine(runtimePath, "Invoke-ADSecurityAudit.ps1");
        if (string.IsNullOrEmpty(runtimePath) || !File.Exists(orchestratorScript))
        {
            await ShowNoticeAsync("Execution Error", "Runtime audit environment resources are missing or invalid. Invoke-ADSecurityAudit.ps1 was not found.");
            return;
        }

        string pwsh = RuntimeHost.FindPowerShellCoreExecutable();
        if (string.IsNullOrEmpty(pwsh))
        {
            string installHint = OperatingSystem.IsWindows()
                ? "PowerShell was not found. Install PowerShell 7 from https://aka.ms/powershell, or ensure Windows PowerShell 5.1 is available."
                : "PowerShell 7+ (pwsh) was not found. Install it, then restart this application.\n\nhttps://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell-on-linux";
            await ShowNoticeAsync("PowerShell Missing", installHint);
            return;
        }

        string targetDomain = TxtDomain.Text?.Trim() ?? string.Empty;
        string server = TxtServer.Text?.Trim() ?? string.Empty;
        string outputPath = TxtOutputPath.Text?.Trim() ?? string.Empty;
        string username = TxtUsername.Text?.Trim() ?? string.Empty;
        string password = TxtPassword.Text ?? string.Empty;

        if (string.IsNullOrWhiteSpace(outputPath))
        {
            await ShowNoticeAsync("Output Path Required", "Choose an output folder for HTML, CSV, and JSON reports.");
            return;
        }

        if (!int.TryParse(TxtInactiveDays.Text?.Trim(), out int inactiveDays) || inactiveDays < 1)
        {
            inactiveDays = 90;
            TxtInactiveDays.Text = "90";
        }

        try
        {
            Directory.CreateDirectory(outputPath);
        }
        catch (Exception ex)
        {
            await ShowNoticeAsync("Output Path Error", $"Could not create the output folder:\n{outputPath}\n\n{ex.Message}");
            return;
        }

        if (!Modules.Any(module => module.IsSelected))
        {
            await ShowNoticeAsync("No Modules Selected", "Select at least one audit module, or use Run All Modules.");
            return;
        }

        List<string> selectedModules = CollectSelectedModuleIds();
        if (selectedModules.Count == 0)
        {
            selectedModules.Add("__none__");
        }

        ProcessStartInfo psi = new ProcessStartInfo
        {
            FileName = pwsh,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = runtimePath
        };

        psi.ArgumentList.Add("-NoProfile");
        psi.ArgumentList.Add("-File");
        psi.ArgumentList.Add(orchestratorScript);
        psi.ArgumentList.Add("-OutputPath");
        psi.ArgumentList.Add(outputPath);
        psi.ArgumentList.Add("-InactiveDays");
        psi.ArgumentList.Add(inactiveDays.ToString());

        if (!string.IsNullOrEmpty(targetDomain))
        {
            psi.ArgumentList.Add("-Domain");
            psi.ArgumentList.Add(targetDomain);
        }

        if (!string.IsNullOrEmpty(server))
        {
            psi.ArgumentList.Add("-Server");
            psi.ArgumentList.Add(server);
        }

        if (ChkSkipRemote.IsChecked == true) { psi.ArgumentList.Add("-SkipRemoteChecks"); }

        psi.ArgumentList.Add("-Modules");
        psi.ArgumentList.Add(string.Join(",", selectedModules));

        if (!string.IsNullOrEmpty(username))
        {
            psi.Environment["AD_AUDIT_USERNAME"] = username;
            psi.Environment["AD_AUDIT_PASSWORD"] = password;
        }

        SetUiExecutingState(true);
        TxtLogConsole.Text = string.Empty;
        AppendConsoleLog($"[*] Launching audit with PowerShell: {pwsh}");
        AppendConsoleLog($"[*] Script: {orchestratorScript}");
        AppendConsoleLog($"[*] Modules: {string.Join(", ", selectedModules)}");
        AppendConsoleLog($"[*] Output: {outputPath}");
        if (!string.IsNullOrEmpty(username))
        {
            AppendConsoleLog($"[*] Alternate credentials: {username}");
        }

        await Task.Run(() =>
        {
            try
            {
                using Process process = new Process { StartInfo = psi };
                _activeAuditProcess = process;

                process.OutputDataReceived += (_, ev) =>
                {
                    if (!string.IsNullOrEmpty(ev.Data))
                    {
                        AppendConsoleLog(ev.Data);
                    }
                };
                process.ErrorDataReceived += (_, ev) =>
                {
                    if (!string.IsNullOrEmpty(ev.Data))
                    {
                        AppendConsoleLog($"[ERROR] {ev.Data}");
                    }
                };

                process.Start();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                process.WaitForExit();
                AppendConsoleLog($"[*] pwsh exit code: {process.ExitCode}");
            }
            catch (Exception ex)
            {
                AppendConsoleLog($"[CRITICAL EXCEPTION] {ex.Message}");
            }
            finally
            {
                _activeAuditProcess = null;
            }
        });

        SetUiExecutingState(false);
        AppendConsoleLog("[*] Audit execution finished.");
        ProgBar.IsIndeterminate = false;
        ProgBar.Value = 100;
    }

    private List<string> CollectSelectedModuleIds()
    {
        HashSet<string> selected = new(
            Modules.Where(m => m.IsSelected && m.Id is not ("RiskScoring" or "Reporting")).Select(m => m.Id),
            StringComparer.OrdinalIgnoreCase);

        return selected.ToList();
    }

    private void BtnStop_Click(object? sender, RoutedEventArgs e)
    {
        try
        {
            Process? process = _activeAuditProcess;
            if (process != null && !process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                AppendConsoleLog("[!] Audit process terminated by user request.");
            }
        }
        catch (Exception ex)
        {
            AppendConsoleLog($"[!] Termination failed: {ex.Message}");
        }

        SetUiExecutingState(false);
    }

    private void SetUiExecutingState(bool isExecuting)
    {
        _isExecuting = isExecuting;
        BtnRunAll.IsEnabled = !isExecuting;
        BtnRunSelected.IsEnabled = !isExecuting;
        BtnStop.IsEnabled = isExecuting;
        ProgBar.IsIndeterminate = isExecuting;
        if (!isExecuting)
        {
            ProgBar.Value = 0;
        }

        ItemsControlModules.IsEnabled = !isExecuting;
        BtnSelectAll.IsEnabled = !isExecuting;
        BtnSelectNone.IsEnabled = !isExecuting;

        TxtStatus.Text = isExecuting ? "Running" : "Ready";
        TxtStatus.Foreground = new SolidColorBrush(Color.Parse(isExecuting ? "#FFB900" : "#6CCB5F"));
        StatusPill.Background = new SolidColorBrush(Color.Parse(isExecuting ? "#3D2E12" : "#1A3328"));
    }

    private void AppendConsoleLog(string line)
    {
        Dispatcher.UIThread.Post(() =>
        {
            TxtLogConsole.Text += line + Environment.NewLine;
            TxtLogConsole.CaretIndex = TxtLogConsole.Text?.Length ?? 0;
        });
    }

    private async void BtnBrowseOutput_Click(object? sender, RoutedEventArgs e)
    {
        IReadOnlyList<IStorageFolder> folders = await StorageProvider.OpenFolderPickerAsync(new FolderPickerOpenOptions
        {
            Title = "Select audit output folder",
            AllowMultiple = false
        });

        if (folders.Count > 0)
        {
            TxtOutputPath.Text = folders[0].Path.LocalPath;
        }
    }

    private async void BtnOpenReport_Click(object? sender, RoutedEventArgs e)
    {
        string reportFile = Path.Combine(TxtOutputPath.Text?.Trim() ?? string.Empty, "AD-Security-Audit-Summary.html");
        if (!File.Exists(reportFile))
        {
            await ShowNoticeAsync("Report Notice", $"Report file not found at:\n{reportFile}");
            return;
        }

        if (!TryOpenPath(reportFile))
        {
            await ShowNoticeAsync("Open Report", $"Report generated at:\n{reportFile}\n\nOpen it in your browser if it did not launch automatically.");
        }
    }

    private async void BtnOpenFolder_Click(object? sender, RoutedEventArgs e)
    {
        string outputDirectory = TxtOutputPath.Text?.Trim() ?? string.Empty;
        if (!Directory.Exists(outputDirectory))
        {
            await ShowNoticeAsync("Open Directory", $"Output directory does not exist yet:\n{outputDirectory}");
            return;
        }

        if (!TryOpenPath(outputDirectory))
        {
            await ShowNoticeAsync("Open Directory", $"Output directory:\n{outputDirectory}");
        }
    }

    private static bool TryOpenPath(string path)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = path,
                    UseShellExecute = true
                });
                return true;
            }

            string[] launchers = { "xdg-open", "gio", "gnome-open", "kde-open" };
            foreach (string launcher in launchers)
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = launcher,
                        UseShellExecute = false
                    };
                    if (launcher == "gio")
                    {
                        psi.ArgumentList.Add("open");
                    }

                    psi.ArgumentList.Add(path);
                    using Process? process = Process.Start(psi);
                    if (process != null)
                    {
                        return true;
                    }
                }
                catch
                {
                    // Try the next launcher.
                }
            }
        }
        catch
        {
            return false;
        }

        return false;
    }

    private async Task ShowNoticeAsync(string title, string message)
    {
        Button ok = new Button
        {
            Content = "OK",
            HorizontalAlignment = Avalonia.Layout.HorizontalAlignment.Right,
            MinWidth = 80
        };

        Window dialog = new Window
        {
            Title = title,
            Width = 480,
            SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false,
            Background = new SolidColorBrush(Color.Parse("#1F1F1F")),
            FontFamily = this.FontFamily,
            Content = new Border
            {
                BorderBrush = new SolidColorBrush(Color.Parse("#3D3D3D")),
                BorderThickness = new Thickness(1),
                Padding = new Thickness(24),
                Child = new StackPanel
                {
                    Spacing = 16,
                    Children =
                    {
                        new TextBlock
                        {
                            Text = title,
                            FontSize = 16,
                            FontWeight = FontWeight.SemiBold,
                            Foreground = Brushes.White
                        },
                        new TextBlock
                        {
                            Text = message,
                            TextWrapping = TextWrapping.Wrap,
                            LineHeight = 20,
                            Foreground = new SolidColorBrush(Color.Parse("#D0D0D0"))
                        },
                        ok
                    }
                }
            }
        };

        ok.Classes.Add("primary");
        ok.Click += (_, _) => dialog.Close();
        await dialog.ShowDialog(this);
    }
}
