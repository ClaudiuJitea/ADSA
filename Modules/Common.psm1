# Common.psm1 - Shared directory access, finding schema, and audit helpers
# PowerShell 5.1+ / PowerShell 7+ (Windows and Linux)

$script:AuditSession = $null
$script:AuditSidCache = @{}
$script:AuditSdCache = @{}
$script:AuditDomainSid = $null

function New-AuditFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$CheckId,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $false)][string]$Subcategory = "",
        [Parameter(Mandatory = $true)][string]$Title,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Critical", "High", "Medium", "Low", "Informational")]
        [string]$Severity,
        [Parameter(Mandatory = $true)]
        [ValidateSet("Passed", "Failed", "Warning", "Informational", "Not Tested", "Error")]
        [string]$Status,
        [Parameter(Mandatory = $false)][int]$RiskScore = 0,
        [Parameter(Mandatory = $false)]
        [ValidateSet("High", "Medium", "Low")]
        [string]$Confidence = "High",
        [Parameter(Mandatory = $false)][int]$AffectedCount = 0,
        [Parameter(Mandatory = $false)][array]$AffectedObjects = @(),
        [Parameter(Mandatory = $false)][array]$Evidence = @(),
        [Parameter(Mandatory = $false)][string]$Recommendation = "",
        [Parameter(Mandatory = $false)][string]$MicrosoftReference = "",
        [Parameter(Mandatory = $false)][string]$MitreTechnique = "",
        [Parameter(Mandatory = $false)][string]$RequiredPermission = "Standard Domain User",
        [Parameter(Mandatory = $false)][string]$DataSource = "Active Directory",
        [Parameter(Mandatory = $false)][datetime]$Timestamp = (Get-Date)
    )

    [PSCustomObject]@{
        CheckId            = $CheckId
        Category           = $Category
        Subcategory        = $Subcategory
        Title              = $Title
        Description        = $Description
        Severity           = $Severity
        Status             = $Status
        RiskScore          = $RiskScore
        Confidence         = $Confidence
        AffectedCount      = $AffectedCount
        AffectedObjects    = @($AffectedObjects)
        Evidence           = @($Evidence)
        Recommendation     = $Recommendation
        MicrosoftReference = $MicrosoftReference
        MitreTechnique     = $MitreTechnique
        RequiredPermission = $RequiredPermission
        DataSource         = $DataSource
        Timestamp          = $Timestamp
    }
}

function New-AuditUnavailableFinding {
    param(
        [string]$CheckId,
        [string]$Category,
        [string]$Reason = "No Active Directory connection is available."
    )
    New-AuditFinding -CheckId $CheckId -Category $Category `
        -Title "Directory connection unavailable" `
        -Description $Reason `
        -Severity "High" -Status "Not Tested" -RiskScore 0 `
        -Recommendation "Install RSAT Active Directory tools on Windows, or supply a domain controller, domain FQDN, and credentials so the audit can bind over LDAP." `
        -RequiredPermission "Standard Domain User" -DataSource "System"
}

function Test-AuditDirectoryAvailable {
    $session = Get-AuditDirectorySession
    return ($null -ne $session -and $session.Provider -ne "None")
}

function Get-AuditDirectorySession {
    return $script:AuditSession
}

function Close-AuditDirectorySession {
    try {
        if ($script:AuditSession -and $script:AuditSession.LdapConnection) {
            $script:AuditSession.LdapConnection.Dispose()
        }
    } catch { }
    $script:AuditSession = $null
}

function Get-AuditCurrentIdentity {
    try {
        return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    } catch { }
    if ($env:USER) { return $env:USER }
    if ($env:USERNAME) { return $env:USERNAME }
    return "unknown"
}

function ConvertTo-AuditHtml {
    param($Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Limit-AuditObjects {
    param([array]$Objects, [int]$Max = 100)
    if ($null -eq $Objects) { return @() }
    $arr = @($Objects)
    if ($arr.Count -le $Max) { return $arr }
    $keep = $arr[0..($Max - 1)]
    return @($keep + "... and $($arr.Count - $Max) more")
}

function Test-AuditUacFlag {
    param($UserAccountControl, [int]$Flag)
    if ($null -eq $UserAccountControl -or $UserAccountControl -eq "") { return $false }
    try {
        return (([int]$UserAccountControl) -band $Flag) -eq $Flag
    } catch {
        return $false
    }
}

function Convert-AuditFileTime {
    param($Value)
    if ($null -eq $Value -or $Value -eq "" -or $Value -eq 0 -or $Value -eq "0") { return $null }
    try {
        return [DateTime]::FromFileTimeUtc([int64]$Value).ToLocalTime()
    } catch {
        return $null
    }
}

function Get-AuditAttr {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object.PSObject.Properties[$Name]) { return $Object.$Name }
    $lower = $Name.ToLowerInvariant()
    foreach ($prop in $Object.PSObject.Properties) {
        if ($prop.Name.ToLowerInvariant() -eq $lower) { return $prop.Value }
    }
    return $null
}

function Get-AuditSam {
    param($Object)
    $sam = Get-AuditAttr $Object "sAMAccountName"
    if ($sam) { return [string]$sam }
    $name = Get-AuditAttr $Object "name"
    if ($name) { return [string]$name }
    return [string](Get-AuditAttr $Object "distinguishedName")
}

function Convert-ADGuidToName {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$GuidString)

    $guidMap = @{
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes (DCSync)"
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All (DCSync)"
        "89e867f0-4a1d-11d1-e9c6-00c04fd7d84f" = "DS-Replication-Get-Changes-In-Filtered-Set"
        "00299570-66d9-11d1-9027-00c04fd7d735" = "User-Force-Change-Password"
        "bf9679c0-0de6-11d0-a285-00aa003049e2" = "Self-Membership"
        "f3a64788-5306-11d1-a9c5-0000f80367c1" = "Validated-SPN"
        "bf9679c5-0de6-11d0-a285-00aa003049e2" = "Write-Member"
        "280f369c-d2b7-49e6-a78c-741e8b9c0560" = "Allowed-To-Authenticate"
        "b7b1b3de-ab09-4242-9e30-9280e721b0e6" = "ms-Mcs-AdmPwd (Legacy LAPS read)"
        "aa4e90cd-d33a-49e6-00e0-81e5-827c86510619" = "msLAPS-Password (Windows LAPS read)"
        "aa4e90cd-d33a-49e6-81e5-827c86510619" = "msLAPS-Password (Windows LAPS read)"
        "e362ed86-b728-0842-b27d-2dea7ac6ba6c" = "msLAPS-EncryptedPassword"
        "72e39547-7b18-11d1-adef-00c04fd8d5cd" = "Validated-DNS-Host-Name"
        "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79" = "msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD)"
        "5b47d60f-6090-40b2-9f37-2a4de88f3063" = "msDS-KeyCredentialLink (Shadow Credentials)"
        "bf967a68-0de6-11d0-a285-00aa003049e2" = "userAccountControl"
        "bf9679a8-0de6-11d0-a285-00aa003049e2" = "scriptPath"
        "f30e3bbe-9ff0-11d1-b603-0000f80367c1" = "gPLink"
        "f30e3bc1-9ff0-11d1-b603-0000f80367c1" = "gPCFileSysPath"
        "28630ebf-41d5-11d1-a9c1-0000f80367c1" = "userPrincipalName"
        "00000000-0000-0000-0000-000000000000" = "All objects / All properties"
    }

    $key = $GuidString.ToLower()
    if ($guidMap.ContainsKey($key)) { return $guidMap[$key] }
    return $GuidString
}

function Get-AuditFunctionalLevelName {
    param($Value)
    switch ("$Value") {
        "0" { "Windows 2000" }
        "1" { "Windows Server 2003 interim" }
        "2" { "Windows Server 2003" }
        "3" { "Windows Server 2008" }
        "4" { "Windows Server 2008 R2" }
        "5" { "Windows Server 2012" }
        "6" { "Windows Server 2012 R2" }
        "7" { "Windows Server 2016" }
        "10" { "Windows Server 2025" }
        default { if ($Value) { [string]$Value } else { "Unknown" } }
    }
}

function Write-AuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [Parameter(Mandatory = $false)][ValidateSet("INFO", "WARN", "ERROR", "DEBUG")][string]$Level = "INFO",
        [Parameter(Mandatory = $false)][string]$LogPath
    )

    $formatted = "[{0}] [{1}] {2}" -f (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"), $Level, $Message
    switch ($Level) {
        "INFO"  { Write-Verbose $formatted }
        "WARN"  { Write-Warning $formatted }
        "ERROR" { Write-Error $formatted }
        "DEBUG" { Write-Debug $formatted }
    }
    if ($LogPath) {
        try { Add-Content -Path $LogPath -Value $formatted -ErrorAction SilentlyContinue } catch { }
    }
}

function Initialize-AuditDirectorySession {
    [CmdletBinding()]
    param(
        [string]$Domain,
        [string]$Server,
        [PSCredential]$Credential,
        [bool]$PreferLdaps = $false
    )

    Close-AuditDirectorySession
    $script:AuditSidCache = @{}
    $script:AuditSdCache = @{}
    $script:AuditDomainSid = $null

    $bindHost = if ($Server) { $Server } elseif ($Domain) { $Domain } else { $null }
    $adParams = @{}
    if ($bindHost) { $adParams["Server"] = $bindHost }
    if ($Credential) { $adParams["Credential"] = $Credential }

    $session = [PSCustomObject]@{
        Provider          = "None"
        Server            = $bindHost
        Domain            = $Domain
        Credential        = $Credential
        AdParams          = $adParams
        DefaultNamingContext = $null
        ConfigurationNamingContext = $null
        SchemaNamingContext = $null
        RootDomainNamingContext = $null
        DnsHostName       = $null
        DomainFunctionality = $null
        ForestFunctionality = $null
        LdapConnection    = $null
        Error             = $null
    }

    if (Get-Module -ListAvailable -Name ActiveDirectory) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $root = Get-ADRootDSE @adParams -ErrorAction Stop
            $session.Provider = "ActiveDirectory"
            $session.DefaultNamingContext = $root.defaultNamingContext
            $session.ConfigurationNamingContext = $root.configurationNamingContext
            $session.SchemaNamingContext = $root.schemaNamingContext
            $session.RootDomainNamingContext = $root.rootDomainNamingContext
            $session.DnsHostName = $root.dnsHostName
            $session.DomainFunctionality = $root.domainFunctionality
            $session.ForestFunctionality = $root.forestFunctionality
            if (-not $session.Domain -and $session.DefaultNamingContext) {
                $session.Domain = ($session.DefaultNamingContext -replace "DC=", "" -replace ",", ".")
            }
            $script:AuditSession = $session
            return $session
        } catch {
            $session.Error = $_.Exception.Message
        }
    }

    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
        $ports = if ($PreferLdaps) { @(636, 389) } else { @(389, 636) }
        if (-not $bindHost) { throw "A domain FQDN or domain controller is required for LDAP on this host." }

        $bound = $false
        $lastError = $null
        foreach ($port in $ports) {
            try {
                $id = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($bindHost, [int]$port, $false, $false)
                $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($id)
                $conn.Timeout = [TimeSpan]::FromSeconds(20)
                $conn.SessionOptions.ProtocolVersion = 3
                $conn.SessionOptions.ReferralChasing = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None
                if ($port -eq 636) { $conn.SessionOptions.SecureSocketLayer = $true }

                $auths = @("Negotiate", "Ntlm", "Basic")
                foreach ($authName in $auths) {
                    try {
                        $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::$authName
                        if ($Credential) {
                            $nc = $Credential.GetNetworkCredential()
                            $conn.Bind((New-Object System.Net.NetworkCredential($nc.UserName, $nc.Password, $nc.Domain)))
                        } else {
                            $conn.Bind()
                        }
                        $bound = $true
                        $session.LdapConnection = $conn
                        $session.Server = $bindHost
                        break
                    } catch {
                        $lastError = $_.Exception.Message
                    }
                }
                if ($bound) { break }
            } catch {
                $lastError = $_.Exception.Message
            }
        }

        if (-not $bound) { throw $lastError }

        $rootReq = New-Object System.DirectoryServices.Protocols.SearchRequest
        $rootReq.DistinguishedName = ""
        $rootReq.Filter = "(objectClass=*)"
        $rootReq.Scope = [System.DirectoryServices.Protocols.SearchScope]::Base
        $rootResp = [System.DirectoryServices.Protocols.SearchResponse]$session.LdapConnection.SendRequest($rootReq)
        $entry = $rootResp.Entries[0]
        $session.Provider = "LDAP"
        $session.DefaultNamingContext = Get-AuditLdapAttributeValue $entry "defaultNamingContext"
        $session.ConfigurationNamingContext = Get-AuditLdapAttributeValue $entry "configurationNamingContext"
        $session.SchemaNamingContext = Get-AuditLdapAttributeValue $entry "schemaNamingContext"
        $session.RootDomainNamingContext = Get-AuditLdapAttributeValue $entry "rootDomainNamingContext"
        $session.DnsHostName = Get-AuditLdapAttributeValue $entry "dnsHostName"
        $session.DomainFunctionality = Get-AuditLdapAttributeValue $entry "domainFunctionality"
        $session.ForestFunctionality = Get-AuditLdapAttributeValue $entry "forestFunctionality"
        if (-not $session.Domain -and $session.DefaultNamingContext) {
            $session.Domain = ($session.DefaultNamingContext -replace "DC=", "" -replace ",", ".")
        }
        $script:AuditSession = $session
        return $session
    } catch {
        $session.Provider = "None"
        $session.Error = $_.Exception.Message
        $script:AuditSession = $session
        return $session
    }
}

function Get-AuditLdapAttributeValue {
    param($Entry, [string]$Name)
    if ($null -eq $Entry -or $null -eq $Entry.Attributes) { return $null }
    if (-not $Entry.Attributes.Contains($Name)) { return $null }
    $attr = $Entry.Attributes[$Name]
    if ($attr.Count -eq 0) { return $null }
    try { return [string]$attr[0] } catch { return $null }
}

function ConvertFrom-AuditLdapEntry {
    param($Entry)
    $map = [ordered]@{ DistinguishedName = $Entry.DistinguishedName }
    foreach ($key in $Entry.Attributes.AttributeNames) {
        $attr = $Entry.Attributes[$key]
        $values = @()
        for ($i = 0; $i -lt $attr.Count; $i++) {
            $item = $attr[$i]
            if ($item -is [byte[]]) {
                if ($key -match "objectSid") {
                    try { $values += (New-Object System.Security.Principal.SecurityIdentifier($item, 0)).Value } catch { $values += [Convert]::ToBase64String($item) }
                } elseif ($key -match "objectGUID") {
                    try { $values += ([guid]$item).Guid } catch { $values += [Convert]::ToBase64String($item) }
                } else {
                    $values += $item
                }
            } else {
                $values += $item
            }
        }
        if ($values.Count -eq 1) { $map[$key] = $values[0] } else { $map[$key] = $values }
    }
    [PSCustomObject]$map
}

function Search-AuditDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LdapFilter,
        [string]$SearchBase,
        [string[]]$Properties = @("distinguishedName", "sAMAccountName", "name", "objectClass", "userAccountControl"),
        [ValidateSet("Base", "OneLevel", "Subtree")][string]$Scope = "Subtree",
        [int]$PageSize = 800
    )

    $session = Get-AuditDirectorySession
    if (-not $session -or $session.Provider -eq "None") { return @() }
    if (-not $SearchBase) { $SearchBase = $session.DefaultNamingContext }
    if (-not $SearchBase) { return @() }

    if ($session.Provider -eq "ActiveDirectory") {
        $scopeEnum = switch ($Scope) {
            "Base" { "Base" }
            "OneLevel" { "OneLevel" }
            default { "Subtree" }
        }
        $params = @{
            LDAPFilter  = $LdapFilter
            SearchBase  = $SearchBase
            SearchScope = $scopeEnum
            Properties  = $Properties
            ErrorAction = "Stop"
        }
        $ad = $session.AdParams
        try {
            return @(Get-ADObject @params @ad)
        } catch {
            try { return @(Get-ADObject -LDAPFilter $LdapFilter -SearchBase $SearchBase -Properties $Properties @ad -ErrorAction Stop) } catch { return @() }
        }
    }

    $results = New-Object System.Collections.Generic.List[object]
    try {
        $request = New-Object System.DirectoryServices.Protocols.SearchRequest
        $request.DistinguishedName = $SearchBase
        $request.Filter = $LdapFilter
        $request.Scope = [System.DirectoryServices.Protocols.SearchScope]::$Scope
        foreach ($p in $Properties) { [void]$request.Attributes.Add($p) }
        if ($Properties -contains "nTSecurityDescriptor") {
            [void]$request.Controls.Add((New-AuditSdFlagControl))
        }
        $page = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($PageSize)
        [void]$request.Controls.Add($page)

        do {
            $response = [System.DirectoryServices.Protocols.SearchResponse]$session.LdapConnection.SendRequest($request)
            foreach ($entry in $response.Entries) {
                [void]$results.Add((ConvertFrom-AuditLdapEntry $entry))
            }
            $cookie = $null
            foreach ($control in $response.Controls) {
                if ($control -is [System.DirectoryServices.Protocols.PageResultResponseControl]) {
                    $cookie = $control.Cookie
                }
            }
            if ($cookie -and $cookie.Length -gt 0) { $page.Cookie = $cookie } else { $cookie = $null }
        } while ($cookie -and $cookie.Length -gt 0)
    } catch {
        Write-AuditLog -Level WARN -Message "LDAP search failed ($LdapFilter): $($_.Exception.Message)"
    }
    return @($results)
}

function Get-AuditGroupMembers {
    param(
        [Parameter(Mandatory = $true)][string]$GroupDn,
        [switch]$Recursive
    )
    $session = Get-AuditDirectorySession
    if (-not $session -or $session.Provider -eq "None") { return @() }

    $escapedDn = Format-AuditLdapFilterValue $GroupDn
    if ($Recursive) {
        $filter = "(memberOf:1.2.840.113556.1.4.1941:=$escapedDn)"
        return @(Search-AuditDirectory -LdapFilter $filter -Properties @("distinguishedName", "sAMAccountName", "name", "objectClass", "userAccountControl", "lastLogonTimestamp", "servicePrincipalName", "adminCount", "pwdLastSet", "primaryGroupID", "objectSid"))
    }

    $group = Search-AuditDirectory -LdapFilter "(objectClass=*)" -SearchBase $GroupDn -Scope Base -Properties @("member")
    if (-not $group) { return @() }
    $members = @(Get-AuditAttr $group[0] "member")
    $resolved = New-Object System.Collections.Generic.List[object]
    foreach ($dn in $members) {
        if (-not $dn) { continue }
        $obj = Search-AuditDirectory -LdapFilter "(objectClass=*)" -SearchBase $dn -Scope Base -Properties @("distinguishedName", "sAMAccountName", "name", "objectClass", "userAccountControl", "objectSid")
        if ($obj) { [void]$resolved.Add($obj[0]) }
    }
    return @($resolved)
}

function Find-AuditGroup {
    param([Parameter(Mandatory = $true)][string]$Name)
    $escaped = Format-AuditLdapFilterValue $Name
    $hits = Search-AuditDirectory -LdapFilter "(&(objectClass=group)(|(sAMAccountName=$escaped)(cn=$escaped)(name=$escaped)))" -Properties @("distinguishedName", "sAMAccountName", "name", "member", "objectSid")
    if ($hits -and $hits.Count -gt 0) { return $hits[0] }
    return $null
}

function New-AuditSdFlagControl {
    # LDAP_SERVER_SD_FLAGS_OID asking for OWNER + GROUP + DACL only. Requesting the SACL
    # as well requires SeSecurityPrivilege, and the DC then omits nTSecurityDescriptor
    # entirely, which is why unprivileged ACL reads fail without this control.
    try {
        return New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl([System.DirectoryServices.Protocols.SecurityMasks]"Owner,Group,Dacl")
    } catch {
        return New-Object System.DirectoryServices.Protocols.DirectoryControl("1.2.840.113556.1.4.801", ([byte[]](0x30, 0x03, 0x02, 0x01, 0x07)), $true, $true)
    }
}

function Get-AuditSecurityDescriptor {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)

    if (-not $script:AuditSdCache) { $script:AuditSdCache = @{} }
    if ($script:AuditSdCache.ContainsKey($DistinguishedName)) { return $script:AuditSdCache[$DistinguishedName] }

    $result = [PSCustomObject]@{
        DistinguishedName = $DistinguishedName
        Owner             = $null
        OwnerSid          = $null
        Access            = @()
        Readable          = $false
    }

    try {
        if (Test-Path "AD:\$DistinguishedName" -ErrorAction SilentlyContinue) {
            $acl = Get-Acl -Path "AD:\$DistinguishedName" -ErrorAction Stop
            if ($acl) {
                $rules = New-Object System.Collections.Generic.List[object]
                foreach ($rule in $acl.Access) {
                    $mask = 0
                    try { $mask = [int]$rule.ActiveDirectoryRights } catch { }
                    $sid = $null
                    try { $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $sid = [string]$rule.IdentityReference }
                    [void]$rules.Add([PSCustomObject]@{
                            IdentityReference     = [string]$rule.IdentityReference
                            Sid                   = $sid
                            AccessControlType     = [string]$rule.AccessControlType
                            ActiveDirectoryRights = $mask
                            ObjectType            = $rule.ObjectType
                            IsInherited           = [bool]$rule.IsInherited
                        })
                }
                $result.Access = @($rules)
                $result.Readable = $true
                try { $result.Owner = [string]$acl.Owner } catch { }
                $script:AuditSdCache[$DistinguishedName] = $result
                return $result
            }
        }
    } catch { }

    $session = Get-AuditDirectorySession
    if ($session -and $session.Provider -eq "LDAP" -and $session.LdapConnection) {
        try {
            $request = New-Object System.DirectoryServices.Protocols.SearchRequest($DistinguishedName, "(objectClass=*)", [System.DirectoryServices.Protocols.SearchScope]::Base, @("nTSecurityDescriptor"))
            [void]$request.Controls.Add((New-AuditSdFlagControl))
            $response = [System.DirectoryServices.Protocols.SearchResponse]$session.LdapConnection.SendRequest($request)
            if ($response.Entries.Count -gt 0 -and $response.Entries[0].Attributes.Contains("nTSecurityDescriptor")) {
                $bytes = $response.Entries[0].Attributes["nTSecurityDescriptor"][0]
                $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor($bytes, 0)
                $rules = New-Object System.Collections.Generic.List[object]
                if ($raw.DiscretionaryAcl) {
                    foreach ($ace in $raw.DiscretionaryAcl) {
                        $objectType = [guid]::Empty
                        if ($ace -is [System.Security.AccessControl.ObjectAce]) { $objectType = $ace.ObjectAceType }
                        $sidValue = $null
                        try { $sidValue = $ace.SecurityIdentifier.Value } catch { }
                        $mask = 0
                        try { $mask = [int]$ace.AccessMask } catch { }
                        [void]$rules.Add([PSCustomObject]@{
                                IdentityReference     = (Resolve-AuditSid -Sid $sidValue)
                                Sid                   = $sidValue
                                AccessControlType     = $(if ("$($ace.AceQualifier)" -like "AccessAllowed*") { "Allow" } else { "Deny" })
                                ActiveDirectoryRights = $mask
                                ObjectType            = $objectType
                                IsInherited           = (($ace.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited) -ne 0)
                            })
                    }
                }
                $result.Access = @($rules)
                $result.Readable = $true
                if ($raw.Owner) {
                    $result.OwnerSid = $raw.Owner.Value
                    $result.Owner = Resolve-AuditSid -Sid $raw.Owner.Value
                }
            }
        } catch { }
    }

    $script:AuditSdCache[$DistinguishedName] = $result
    return $result
}

function Get-AuditAccessRules {
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)
    return @((Get-AuditSecurityDescriptor -DistinguishedName $DistinguishedName).Access)
}

function Get-AuditObjectOwner {
    param([Parameter(Mandatory = $true)][string]$DistinguishedName)
    return (Get-AuditSecurityDescriptor -DistinguishedName $DistinguishedName).Owner
}

function Test-AuditDangerousAccessMask {
    param([int]$Mask)
    $genericAll = 0x10000000
    $writeDacl = 0x00040000
    $writeOwner = 0x00080000
    $genericWrite = 0x40000000
    $writeProperty = 0x00000020
    return (($Mask -band $genericAll) -ne 0) -or (($Mask -band $writeDacl) -ne 0) -or (($Mask -band $writeOwner) -ne 0) -or (($Mask -band $genericWrite) -ne 0) -or (($Mask -band $writeProperty) -ne 0)
}

function Get-AuditAceRightNames {
    param([int]$Mask)
    $names = New-Object System.Collections.Generic.List[string]
    if (($Mask -band 0x00000001) -ne 0) { [void]$names.Add("CreateChild") }
    if (($Mask -band 0x00000002) -ne 0) { [void]$names.Add("DeleteChild") }
    if (($Mask -band 0x00000008) -ne 0) { [void]$names.Add("Self") }
    if (($Mask -band 0x00000020) -ne 0) { [void]$names.Add("WriteProperty") }
    if (($Mask -band 0x00000040) -ne 0) { [void]$names.Add("DeleteTree") }
    if (($Mask -band 0x00000100) -ne 0) { [void]$names.Add("ExtendedRight") }
    if (($Mask -band 0x00010000) -ne 0) { [void]$names.Add("Delete") }
    if (($Mask -band 0x00040000) -ne 0) { [void]$names.Add("WriteDacl") }
    if (($Mask -band 0x00080000) -ne 0) { [void]$names.Add("WriteOwner") }
    if (($Mask -band 0x10000000) -ne 0) { [void]$names.Add("GenericAll") }
    if (($Mask -band 0x40000000) -ne 0) { [void]$names.Add("GenericWrite") }
    if ($names.Count -eq 0) { return "mask=$Mask" }
    return ($names -join ", ")
}

function Test-AuditControlRight {
    <#
        Decides whether an ACE grants effective control of the target object.
        Unlike Test-AuditDangerousAccessMask, a property write scoped to a single
        harmless attribute is not reported: only writes to attributes that lead to
        takeover (group membership, RBCD, shadow credentials, SPN, GPO paths, LAPS)
        are treated as control.
    #>
    param(
        [int]$Mask,
        $ObjectType
    )

    $genericAll = 0x10000000
    $writeDacl = 0x00040000
    $writeOwner = 0x00080000
    $genericWrite = 0x40000000
    $writeProperty = 0x00000020
    $allChildren = 0x00000001

    if ((($Mask -band $genericAll) -ne 0) -or (($Mask -band $writeDacl) -ne 0) -or (($Mask -band $writeOwner) -ne 0)) { return $true }
    if (($Mask -band $genericWrite) -ne 0) { return $true }

    if (($Mask -band $writeProperty) -ne 0 -or ($Mask -band $allChildren) -ne 0) {
        $guid = "$ObjectType"
        if ([string]::IsNullOrWhiteSpace($guid) -or $guid -eq "00000000-0000-0000-0000-000000000000") { return $true }
        $takeoverAttributes = @(
            "bf9679c0-0de6-11d0-a285-00aa003049e2", # member
            "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79", # msDS-AllowedToActOnBehalfOfOtherIdentity
            "5b47d60f-6090-40b2-9f37-2a4de88f3063", # msDS-KeyCredentialLink
            "f3a64788-5306-11d1-a9c5-0000f80367c1", # servicePrincipalName
            "bf967a68-0de6-11d0-a285-00aa003049e2", # userAccountControl
            "bf9679a8-0de6-11d0-a285-00aa003049e2", # scriptPath
            "f30e3bbe-9ff0-11d1-b603-0000f80367c1", # gPLink
            "f30e3bc1-9ff0-11d1-b603-0000f80367c1", # gPCFileSysPath
            "28630ebf-41d5-11d1-a9c1-0000f80367c1", # userPrincipalName
            "b7b1b3de-ab09-4242-9e30-9280e721b0e6", # ms-Mcs-AdmPwd
            "e362ed86-b728-0842-b27d-2dea7ac6ba6c"  # msLAPS-EncryptedPassword
        )
        return ($takeoverAttributes -contains $guid.ToLowerInvariant())
    }

    return $false
}

function Test-AuditTier0Identity {
    param([string]$Identity)
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $false }
    $patterns = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Domain Controllers",
        "Enterprise Domain Controllers", "Enterprise Read-only Domain Controllers", "SYSTEM",
        "NT AUTHORITY", "CREATOR OWNER", "SELF", "Key Admins", "Enterprise Key Admins",
        "Cert Publishers", "S-1-5-32-544", "S-1-5-18", "S-1-5-9", "S-1-5-10"
    )
    foreach ($p in $patterns) { if ($Identity -like "*$p*") { return $true } }
    # Domain-relative RIDs: Administrator(500), Domain Admins(512), Domain Controllers(516),
    # Cert Publishers(517), Schema Admins(518), Enterprise Admins(519), RODCs(521),
    # Key Admins(526), Enterprise Key Admins(527).
    if ($Identity -match 'S-1-5-21-[\d-]+-(500|512|516|517|518|519|521|526|527)(\s|\)|$)') { return $true }
    return $false
}

function Test-AuditUnresolvedSid {
    param([string]$Identity)
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $false }
    # Resolve-AuditSid returns "name (SID)" once a principal is found, so a bare
    # domain SID means the trustee no longer exists in the directory.
    return ($Identity -match '^S-1-5-21-[\d-]+-\d+$')
}

function Get-AuditDomainSid {
    if ($script:AuditDomainSid) { return $script:AuditDomainSid }
    $session = Get-AuditDirectorySession
    if (-not $session -or -not $session.DefaultNamingContext) { return $null }
    $domain = Search-AuditDirectory -LdapFilter "(objectClass=*)" -SearchBase $session.DefaultNamingContext -Scope Base -Properties @("objectSid")
    if ($domain -and $domain.Count -gt 0) {
        $sid = ConvertTo-AuditSidString (Get-AuditAttr $domain[0] "objectSid")
        if ($sid) {
            $script:AuditDomainSid = $sid
            return $sid
        }
    }
    return $null
}

function Get-AuditTier0PrincipalSids {
    <#
        Returns the SIDs of every principal that is already Tier 0 (nested members of
        the Tier 0 groups plus the built-in Administrator), so other checks can decide
        whether a trustee is really an escalation or just an existing admin.
    #>
    $sids = New-Object 'System.Collections.Generic.HashSet[string]'
    $domainSid = Get-AuditDomainSid
    if ($domainSid) {
        foreach ($rid in @(500, 512, 516, 518, 519, 521, 526, 527)) { [void]$sids.Add("$domainSid-$rid") }
    }
    foreach ($wellKnown in @("S-1-5-18", "S-1-5-9", "S-1-5-32-544")) { [void]$sids.Add($wellKnown) }

    foreach ($groupName in @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")) {
        $group = Find-AuditGroup -Name $groupName
        if (-not $group) { continue }
        $dn = Get-AuditAttr $group "distinguishedName"
        if (-not $dn) { continue }
        foreach ($member in @(Get-AuditGroupMembers -GroupDn $dn -Recursive)) {
            $sid = ConvertTo-AuditSidString (Get-AuditAttr $member "objectSid")
            if ($sid) { [void]$sids.Add($sid) }
        }
    }
    return $sids
}

function Test-AuditAnonymousUserEnumeration {
    $session = Get-AuditDirectorySession
    if (-not $session -or -not $session.Server) { return $false }
    try {
        Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
        $id = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($session.Server, 389, $false, $false)
        $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($id)
        $conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
        $conn.SessionOptions.ProtocolVersion = 3
        $conn.Bind()
        $req = New-Object System.DirectoryServices.Protocols.SearchRequest($session.DefaultNamingContext, "(&(objectClass=user)(objectCategory=person))", [System.DirectoryServices.Protocols.SearchScope]::Subtree, @("sAMAccountName"))
        $req.SizeLimit = 1
        $resp = [System.DirectoryServices.Protocols.SearchResponse]$conn.SendRequest($req)
        $conn.Dispose()
        return ($resp.Entries.Count -gt 0)
    } catch {
        return $false
    }
}

function Format-AuditLdapFilterValue {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return "" }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        $code = [int][char]$ch
        if ($ch -eq '\' -or $ch -eq '*' -or $ch -eq '(' -or $ch -eq ')' -or $code -eq 0) {
            [void]$sb.Append(('\{0:x2}' -f $code))
        } else {
            [void]$sb.Append($ch)
        }
    }
    return $sb.ToString()
}

function ConvertTo-AuditSidString {
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Security.Principal.SecurityIdentifier]) { return $Value.Value }
    if ($Value -is [byte[]]) {
        try { return (New-Object System.Security.Principal.SecurityIdentifier($Value, 0)).Value } catch { return $null }
    }
    $text = [string]$Value
    if ($text -match '^S-1-') { return $text }
    return $text
}

function Get-AuditMostSpecificClass {
    param($Object)
    $oc = @(Get-AuditAttr $Object "objectClass")
    if ($oc.Count -eq 0) { return "" }
    return [string]($oc | Select-Object -Last 1)
}

function Test-AuditBroadIdentity {
    param([string]$Identity)
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $false }
    return ($Identity -match "Everyone|Authenticated Users|Domain Users|Domain Computers|Anonymous|ANONYMOUS LOGON|S-1-1-0|S-1-5-11|S-1-5-7|S-1-5-32-545")
}

function Resolve-AuditSid {
    param([string]$Sid)
    if ([string]::IsNullOrWhiteSpace($Sid)) { return $Sid }
    if ($Sid -notmatch '^S-1-') { return $Sid }
    if ($script:AuditSidCache -and $script:AuditSidCache.ContainsKey($Sid)) {
        return $script:AuditSidCache[$Sid]
    }

    $resolved = $Sid
    $wellKnown = @{
        "S-1-1-0"      = "Everyone"
        "S-1-5-7"      = "ANONYMOUS LOGON"
        "S-1-5-11"     = "Authenticated Users"
        "S-1-5-18"     = "SYSTEM"
        "S-1-5-32-544" = "Administrators"
        "S-1-5-32-545" = "Users"
        "S-1-5-32-546" = "Guests"
        "S-1-5-32-548" = "Account Operators"
        "S-1-5-32-549" = "Server Operators"
        "S-1-5-32-550" = "Print Operators"
        "S-1-5-32-551" = "Backup Operators"
        "S-1-5-32-552" = "Replicator"
    }
    if ($wellKnown.ContainsKey($Sid)) {
        $resolved = "$($wellKnown[$Sid]) ($Sid)"
    } else {
        try {
            $sidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $bytes = New-Object byte[] $sidObj.BinaryLength
            $sidObj.GetBinaryForm($bytes, 0)
            $hex = ($bytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
            $hit = Search-AuditDirectory -LdapFilter "(objectSid=$hex)" -Properties @("sAMAccountName", "name", "distinguishedName")
            if ($hit -and $hit.Count -gt 0) {
                $sam = Get-AuditSam $hit[0]
                if ($sam) { $resolved = "$sam ($Sid)" }
            }
        } catch { }
    }

    if (-not $script:AuditSidCache) { $script:AuditSidCache = @{} }
    $script:AuditSidCache[$Sid] = $resolved
    return $resolved
}

function Get-AuditSecurityDescriptorTrustees {
    <#
        Parses an attribute that stores a raw security descriptor
        (msDS-AllowedToActOnBehalfOfOtherIdentity) and returns the trustees it grants,
        which is the set of principals allowed to impersonate users to the resource.
    #>
    param($Value)
    $trustees = @()
    if ($null -eq $Value) { return $trustees }
    $bytes = $null
    $raw = $null
    if ($Value -is [byte[]]) {
        $bytes = $Value
    } elseif ($Value -is [System.Security.AccessControl.RawSecurityDescriptor]) {
        $raw = $Value
    } else {
        try { $bytes = [Convert]::FromBase64String([string]$Value) } catch { return $trustees }
    }
    try {
        if ($null -eq $raw) {
            if ($null -eq $bytes) { return $trustees }
            $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor($bytes, 0)
        }
        if ($raw.DiscretionaryAcl) {
            foreach ($ace in $raw.DiscretionaryAcl) {
                try { $trustees += (Resolve-AuditSid -Sid $ace.SecurityIdentifier.Value) } catch { }
            }
        }
    } catch { }
    return @($trustees | Select-Object -Unique)
}

function Add-AuditCheckResult {
    param(
        [Parameter(Mandatory = $true)][System.Collections.Generic.List[PSCustomObject]]$Findings,
        [Parameter(Mandatory = $true)][string]$CheckId,
        [Parameter(Mandatory = $true)][string]$Category,
        [string]$Subcategory = "",
        [Parameter(Mandatory = $true)][string]$FailTitle,
        [Parameter(Mandatory = $true)][string]$PassTitle,
        [Parameter(Mandatory = $true)][string]$FailDescription,
        [string]$PassDescription = "No matching objects were found.",
        $Items,
        [string]$Severity = "High",
        [int]$RiskScore = 15,
        [string]$Recommendation = "",
        [string]$MitreTechnique = "",
        [string]$DataSource = "Active Directory",
        [string]$MicrosoftReference = "",
        [ValidateSet("Failed", "Warning")][string]$FailStatus = "Failed"
    )

    $list = @()
    if ($null -ne $Items) { $list = @($Items | Where-Object { $_ -ne $null -and "$_" -ne "" }) }
    if ($list.Count -gt 0) {
        [void]$Findings.Add((New-AuditFinding -CheckId $CheckId -Category $Category -Subcategory $Subcategory `
                -Title $FailTitle -Description $FailDescription -Severity $Severity -Status $FailStatus `
                -RiskScore $RiskScore -AffectedCount $list.Count -AffectedObjects (Limit-AuditObjects $list) `
                -Evidence $list -Recommendation $Recommendation -MitreTechnique $MitreTechnique `
                -MicrosoftReference $MicrosoftReference -DataSource $DataSource))
    } else {
        [void]$Findings.Add((New-AuditFinding -CheckId $CheckId -Category $Category -Subcategory $Subcategory `
                -Title $PassTitle -Description $PassDescription -Severity "Informational" -Status "Passed" `
                -DataSource $DataSource))
    }
}

Export-ModuleMember -Function @(
    "New-AuditFinding",
    "New-AuditUnavailableFinding",
    "Test-AuditDirectoryAvailable",
    "Get-AuditDirectorySession",
    "Close-AuditDirectorySession",
    "Initialize-AuditDirectorySession",
    "Search-AuditDirectory",
    "Get-AuditGroupMembers",
    "Find-AuditGroup",
    "Get-AuditAccessRules",
    "Get-AuditSecurityDescriptor",
    "Get-AuditSecurityDescriptorTrustees",
    "Get-AuditObjectOwner",
    "Get-AuditAceRightNames",
    "Get-AuditDomainSid",
    "Get-AuditTier0PrincipalSids",
    "Test-AuditControlRight",
    "Test-AuditTier0Identity",
    "Test-AuditUnresolvedSid",
    "Get-AuditAttr",
    "Get-AuditSam",
    "Get-AuditCurrentIdentity",
    "ConvertTo-AuditHtml",
    "Limit-AuditObjects",
    "Test-AuditUacFlag",
    "Convert-AuditFileTime",
    "Convert-ADGuidToName",
    "Get-AuditFunctionalLevelName",
    "Write-AuditLog",
    "Test-AuditDangerousAccessMask",
    "Test-AuditAnonymousUserEnumeration",
    "Format-AuditLdapFilterValue",
    "ConvertTo-AuditSidString",
    "Get-AuditMostSpecificClass",
    "Test-AuditBroadIdentity",
    "Resolve-AuditSid",
    "Add-AuditCheckResult"
)
