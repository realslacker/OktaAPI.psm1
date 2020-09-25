# module variables
$ScriptPath = Split-Path (Get-Variable MyInvocation -Scope Script).Value.Mycommand.Definition -Parent
$ModuleName = (Get-Item (Get-Variable MyInvocation -Scope Script).Value.Mycommand.Definition).BaseName

# include module header
. ( Join-Path $ScriptPath 'inc\Header.ps1' )
 
# note that in development both public and private functions are exposed
Get-ChildItem -Path ( Join-Path $ScriptPath 'functions' ) -Recurse -Filter "*.ps1" -File |
    ForEach-Object {
    
        . $_.FullName
        
        ([System.Management.Automation.Language.Parser]::ParseInput((Get-Content -Path $_.FullName -Raw), [ref]$null, [ref]$null)).FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false) |
            ForEach-Object {
                Export-ModuleMember $_.Name
            }
        
    }

# include module footer
. ( Join-Path $ScriptPath 'inc\Footer.ps1' )