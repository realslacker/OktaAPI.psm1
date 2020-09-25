# headers that will be sent to Okta
$__Headers    = @{
    Accept          = 'application/json'
    'Content-Type'  = 'application/json'
}

# the tenant base URI, set by Initialize-OktaAPI
$__BaseUri    = $null

# determine the OS type for user agent string
if ( $PSVersionTable.PSVersion -lt [version]'6.0' -or $IsWindows ) {

    $__OS = 'Windows'

} elseif ( $IsLinux ) {

    $__OS = 'Linux'

} elseif ( $IsMacOS ) {

    $__OS = 'MacOS'

} else {

    $__OS = 'Undefined'

}

# set the user agent string
# $Script:__UserAgent = "OktaAPIWindowsPowerShell/0.1" # Old user agent.
# default: "Mozilla/5.0 (Windows NT; Windows NT 6.3; en-US) WindowsPowerShell/5.1.14409.1012"
$__UserAgent  = 'okta-api-powershell/{0} powershell/{1} {2}/{3}' -f $MyInvocation.MyCommand.Module.Version, $PSVersionTable.PSVersion, $__OS, [Environment]::OSVersion.Version

# force TLS 1.2
# see https://www.codyhosterman.com/2016/06/force-the-invoke-restmethod-powershell-cmdlet-to-use-tls-1-2/
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

