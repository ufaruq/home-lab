# Read-only discovery; omit registry secrets, service command lines, account passwords and environment.
$ErrorActionPreference = 'Stop'
$report = [ordered]@{}
$report.os = Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture
$report.users = Get-LocalUser | Select-Object Name,Enabled,SID
$report.groups = Get-LocalGroup | ForEach-Object {
  $group = $_
  [pscustomobject]@{Name=$group.Name;SID=[string]$group.SID;Members=@(Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue | Select-Object Name,SID,ObjectClass)}
}
# Avoid Win32_Product: it can trigger MSI consistency checks/repairs.
$report.packages = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } | Where-Object DisplayName | Select-Object DisplayName,DisplayVersion,Publisher
$report.services = Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,StartName
$report.network = Get-NetIPConfiguration | Select-Object InterfaceAlias,IPv4Address,IPv6Address,IPv4DefaultGateway,DNSServer
$report.routes = Get-NetRoute | Select-Object InterfaceAlias,DestinationPrefix,NextHop,RouteMetric
$report.volumes = Get-Volume | Select-Object DriveLetter,FileSystemLabel,FileSystem,Size,SizeRemaining
$report.listening = Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
$report.application_config_file_metadata = @('C:\ProgramData\docker\config\daemon.json','C:\Program Files (x86)\ossec-agent\ossec.conf','C:\Program Files\ossec-agent\ossec.conf') | ForEach-Object { if(Test-Path -LiteralPath $_) {Get-Item -LiteralPath $_ | Select-Object FullName,Length,LastWriteTimeUtc,Attributes} }
$report.discovery_limits = 'Configuration bodies, secrets, application databases and workload contents are not collected.'
$report | ConvertTo-Json -Depth 7 -Compress
