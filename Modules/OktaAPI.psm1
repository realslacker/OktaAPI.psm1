# With credit to https://github.com/mbegan/Okta-PSModule

#region Module Setup ==========================================================

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

# used for UrlEncoding
Add-Type -AssemblyName System.Web

# set the user agent string
# $Script:__UserAgent = "OktaAPIWindowsPowerShell/0.1" # Old user agent.
# default: "Mozilla/5.0 (Windows NT; Windows NT 6.3; en-US) WindowsPowerShell/5.1.14409.1012"
$__UserAgent  = 'okta-api-powershell/{0} powershell/{1} {2}/{3}' -f $MyInvocation.MyCommand.Module.Version, $PSVersionTable.PSVersion, $__OS, [Environment]::OSVersion.Version

# force TLS 1.2
# see https://www.codyhosterman.com/2016/06/force-the-invoke-restmethod-powershell-cmdlet-to-use-tls-1-2/
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# define OktaResult class
# thanks /u/bis for the help
# https://www.reddit.com/r/PowerShell/comments/i06wi6/is_it_possible_to_extend_a_collection_object_with/fznrdkb/
class OktaResult : System.Collections.ArrayList {

    [uri]$SelfUri
    [uri]$NextUri
    [int]$RateLimit
    [int]$RemainingLimit
    [int]$SecondsToReset
    hidden [pscustomobject]$RawResponse

    OktaResult() {}
    OktaResult( [int]$Capacity ) : base( $Capacity ) {}
    OktaResult( [System.Collections.ICollection]$Collection ) : base( $Collection ) {}

}

#endregion Module Setup =======================================================

#region Core Functions ========================================================

<#
.SYNOPSIS
 Initialize Okta API settings for module

.DESCRIPTION
 Initialize Okta API settings for module. Call Initialize-OktaAPI before calling Okta API functions.

.PARAMETER Token
 API Token

.PARAMETER BaseUri
 Your Okta tenant URI. Ex: https://tenant_name.oka.com/
 #>
function Initialize-OktaAPI {

    [CmdletBinding()]
    param(
        
        [Parameter( Mandatory, Position=1 )]
        [string]
        $Token,
        
        [Parameter( Mandatory, Position=2 )]
        [Alias( 'BaseUrl' )]
        [uri]
        $BaseUri
        
    )

    Write-Verbose ( 'Token: ' + $Token )
    Write-Verbose ( 'BaseUri: ' + $BaseUri )
    
    $Script:__Headers.Authorization = "SSWS $Token"
    $Script:__BaseUri = $BaseUri

}


<#
.SYNOPSIS
 Call an Okta API Method

.DESCRIPTION
 Call an Okta API Method and return the resulting set of objects.

.PARAMETER Method
 What HTTP method to use, for example GET, POST, DELETE

.PARAMETER Path
 The portion of the URI relative to your tenant URI.
 Ex: /api/v1/users

.PARAMETER Body
 A request body that should be sent. Will be encoded as JSON.

.EXAMPLE
 Invoke-OktaMethod Get '/api/v1/users'
 #>
 function Invoke-OktaMethod {
    
    [CmdletBinding()]
    param(
        
        [Parameter( Mandatory, Position=1 )]
        [Microsoft.PowerShell.Commands.WebRequestMethod]
        $Method,

        [Parameter( Mandatory, Position=2 )]
        [Alias( 'Url', 'Uri' )]
        [string]
        $Path,

        [Parameter( Position=3 )]
        $Body
        
    )

    return ( Invoke-OktaRestMethod @PSBoundParameters )

}


<#
.SYNOPSIS
 Call a paged Okta API Method

.DESCRIPTION
 Call an Okta API Method and return the resulting set of objects and links.

.PARAMETER Path
 The portion of the URI relative to your tenant URI.
 Ex: /api/v1/users

.PARAMETER Body
 A request body that should be sent. Will be encoded as JSON.

.PARAMETER All
 Return all results.

.PARAMETER First
 Return first N results.

.EXAMPLE
 Invoke-OktaPagedMethod '/api/v1/logs?limit=100'

#>
function Invoke-OktaPagedMethod {
    
    [CmdletBinding( DefaultParameterSetName='ParsedResponse' )]
    param(
        
        [Parameter( Mandatory, Position=1 )]
        [Alias( 'Url', 'Uri' )]
        [string]
        $Path,

        $Body,

        [Parameter( ParameterSetName='All' )]
        [switch]
        $All,

        [Parameter( ParameterSetName='First' )]
        [int]
        $First,

        [Parameter( ParameterSetName='DontEnumerate', DontShow )]
        [switch]
        $DontEnumerate
        
    )

    $Results = Invoke-OktaRestMethod -Method Get @PSBoundParameters

    if ( -not $All -and -not $First ) {

        if ( $DontEnumerate ) {

            Write-Output -NoEnumerate $Results
            return
        
        } else {

            return $Results

        }

    }

    $Results |
        Where-Object { $All -or $First-- -gt 0 }

    if ( $Results.NextUri -and ( $All -or $First -gt 0 ) ) {

        # if the remaining limit reaches 0 we pause
        if ( $Results.RemainingLimit ) {

            Write-Warning ( 'Rate limit exceeded, pausing for {0} seconds.' -f $Results.SecondsToReset )
            Start-Sleep $Results.SecondsToReset

        }

        $ParamSplat = @{}

        if ( $All   ) { $ParamSplat.All   = $All   }
        if ( $First ) { $ParamSplat.First = $First }

        Invoke-OktaPagedMethod $Results.NextUri @ParamSplat

    }

}


<#
.SYNOPSIS
 Call a rest method against an Okta API

.DESCRIPTION
 Call a rest method against an Okta API and return the resulting
 set of objects, links, and API limits.

.PARAMETER Method
 What HTTP method to use, for example GET, POST, DELETE

.PARAMETER Path
 The portion of the URI relative to your tenant URI.
 Ex: /api/v1/users

.PARAMETER Body
 A request body that should be sent. Will be encoded as JSON.

.EXAMPLE
 Invoke-OktaRestMethod Get '/api/v1/logs?limit=100'
#>
function Invoke-OktaRestMethod {
    
    [CmdletBinding()]
    param(
        
        [Parameter( Mandatory, Position=1 )]
        [Microsoft.PowerShell.Commands.WebRequestMethod]
        $Method,

        [Parameter( Mandatory, Position=2 )]
        [Alias( 'Url', 'Uri', 'NextUri' )]
        [string]
        $Path,

        $Body,

        [Parameter( ValueFromRemainingArguments, DontShow )]
        $IgnoredParameters
        
    )

    if ( $null -eq $Script:__BaseUri ) {

        Write-Error 'Please call Initialize-OktaAPI first or include a fully qualified URI'
        return

    }

    if ( $Path -notmatch 'https?://' ) {

        $Path = $Script:__BaseUri.AbsoluteUri + $Path.Trim( '/' )

    }

    $InvokeRequestSplat = @{
        Uri                 = $Path
        Method              = $Method
        Headers             = $Script:__Headers
        UserAgent           = $Script:__UserAgent
        UseBasicParsing     = $true
    }

    if ( $Body ) {

        # max depth is 100. pipe works better than InputObject
        $InvokeRequestSplat.Body = $Body | ConvertTo-Json -Compress -Depth 100

    }

    try {

        $Response = Invoke-WebRequest @InvokeRequestSplat

    } catch {
    
        $ResponseStream = $_.Exception.Response.GetResponseStream()
        $ResponseReader = New-Object System.IO.StreamReader( $ResponseStream )
        $ResponseContent = $ResponseReader.ReadToEnd() | ConvertFrom-Json

        Write-Error ( "Error {0}: {1}`r`nError ID: {2}`r`n" -f $ResponseContent.errorCode, $ResponseContent.errorSummary, $ResponseContent.errorId, ( $ResponseContent.errorCauses -join "`r`n" ) )
        return
    
    }

    # for requests with no response we just return
    if ( $Response.StatusCode -eq 204 ) { return }

    [OktaResult]$ResponseObject = [pscustomobject[]]( ConvertFrom-Json -InputObject $Response.Content )
    $ResponseObject.RawResponse = $Response

    if ( $Response.Headers.link ) {

        $Response.Headers.link.Split(',') |
            Where-Object { $_ -match '<(?<Uri>.*)>; rel="(?<Name>.*)"' } |
            ForEach-Object { $ResponseObject.( $Matches.Name + 'Uri' ) = $Matches.Uri }

    }

    $ResponseObject.RateLimit      = $Response.Headers.'X-Rate-Limit-Limit'
    $ResponseObject.RemainingLimit = [int]$Response.Headers.'X-Rate-Limit-Remaining' # how many calls are remaining
    $ResponseObject.SecondsToReset = [math]::Ceiling( ( [DateTimeOffset]::FromUnixTimeSeconds( [int][string]$Response.Headers.'X-Rate-Limit-Reset' ).DateTime.ToLocalTime() - (Get-Date) ).TotalSeconds )

    if ( $ResponseObject.RemainingLimit / $ResponseObject.RateLimit -lt 0.1 ) {

        Write-Warning ( 'Approaching rate limit, {0}/{1} requests remaining. Rate limit will reset in {2} seconds.' -f $ResponseObject.RemainingLimit, $ResponseObject.RateLimit, $ResponseObject.SecondsToReset )

    }

    Write-Output -NoEnumerate $ResponseObject

}

#endregion Core Functions =====================================================

#region Apps - https://developer.okta.com/docs/reference/api/apps

<#
.SYNOPSIS
 Adds a new application to your Okta organization

.DESCRIPTION
 Adds a new application to your Okta organization

.PARAMETER AppConfig
 See the [Application Object Model](https://developer.okta.com/docs/reference/api/apps/#application-object)

.PARAMETER Activate
 Executes [activation lifecycle](https://developer.okta.com/docs/reference/api/apps/#activate-application) operation when creating the app

.EXAMPLE
 $BookmarkAppConfig = @{
     name = 'bookmark'
     label = 'Sample Bookmark App'
     signOnMode = 'BOOKMARK'
     settings = @{
         app = @{
             requestIntegration = $false
             url = 'https://example.com/bookmark.html'
         }
     }
 }
 Add-OktaApp -AppConfig $BookmarkAppConfig -Activate

.LINK https://developer.okta.com/docs/reference/api/apps/#add-application

.LINK https://developer.okta.com/docs/reference/api/apps/#application-object

#>
function Add-OktaApp {

    param(
        
        [Parameter( Mandatory, Position=1, ValueFromPipeline )]
        [PSCustomObject[]]
        $AppConfig,
        
        [switch]
        $Activate
        
    )

    process {

        $AppConfig | ForEach-Object {

            Invoke-OktaMethod POST "/api/v1/apps?activate=$Activate" $_

        }

    }

}


<#
.SYNOPSIS
 Fetches an application from your Okta organization by id

.DESCRIPTION
 Fetches an application from your Okta organization by id

.PARAMETER ApplicationId
 ID of an app

.LINK https://developer.okta.com/docs/reference/api/apps/#get-application

#>
function Get-OktaApp {

    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'AppId' )]
        [string[]]
        $ApplicationId

    )

    process {

        $ApplicationId | ForEach-Object {
            
            Invoke-OktaMethod GET "/api/v1/apps/$_"

        }

    }

}


<#
.SYNOPSIS
 Enumerates apps added to your organization with pagination.

.DESCRIPTION
 Enumerates apps added to your organization with pagination. A subset of apps can be returned that match a supported filter expression or query.

.PARAMETER After
 Specifies the pagination cursor for the next page of apps

.PARAMETER Expand
 Traverses the *users* link relationship and optionally embeds the [Application User](https://developer.okta.com/docs/reference/api/apps/#application-user-object) resource

.PARAMETER Filter
 Filters apps by *status*, *user.id*, *group.id* or *credentials.signing.kid* expression

.PARAMETER Limit
 Specifies the number of results per page (maximum 200)

.PARAMETER Query
 Searches the *name* or *displayName* property of applications

.PARAMETER All
 Return all results.

.PARAMETER First
 Return first N results.

.LINK https://developer.okta.com/docs/reference/api/apps/#list-applications

#>
function Find-OktaApps {

    [CmdletBinding( DefaultParameterSetName='Default' )]
    param(

        [string]
        $After,

        [string]
        $Expand,

        [string]
        $Filter,

        [ValidateRange( 1, 200 )]
        [int]
        $Limit = 20,

        [string]
        $Query,

        [Parameter( Mandatory, ParameterSetName='All' )]
        [switch]
        $All,

        [Parameter( Mandatory, ParameterSetName='First' )]
        [int]
        $First

    )

    $ParamSplat = @{}

    switch ( $PSCmdlet.ParameterSetName ) {

        'All' { $ParamSplat.All = $All }

        'First' {

            $ParamSplat.First = $First
            $Limit = [math]::Min( $First, 200 )

        }

    }

    $Path = "/api/v1/apps?after=$After&filter=$Filter&limit=$Limit&expand=$Expand&q=$Query"
    
    Invoke-OktaPagedMethod $Path @ParamSplat
    
}

<#
.SYNOPSIS
 Updates an application in your organization

.DESCRIPTION
 Updates an application in your organization

.PARAMETER ApplicationId
 *ID* of an app to update

.PARAMETER AppConfig
 Updated AppConfig, see the [Application Object Model](https://developer.okta.com/docs/reference/api/apps/#application-object)

.EXAMPLE
 $BookmarkAppConfig = @{
     name = 'bookmark'
     label = 'Sample Bookmark App - UPDATED'
     signOnMode = 'BOOKMARK'
     settings = @{
         app = @{
             requestIntegration = $false
             url = 'https://example.com/bookmark.html'
         }
     }
 }
 Update-OktaApp -ApplicationId 0oabkvBLDEKCNXBGYUAS -AppConfig $BookmarkAppConfig

.LINK https://developer.okta.com/docs/reference/api/apps/#update-application

.LINK https://developer.okta.com/docs/reference/api/apps/#application-object

#>
function Update-OktaApp {

    param(

        [Parameter( Mandatory, Position=1 )]
        [Alias( 'Id', 'AppId' )]
        [string]
        $ApplicationId,
        
        [Parameter( Mandatory, Position=2 )]
        [pscustomobject]
        $AppConfig
        
    )
    
    Invoke-OktaMethod Put "/api/v1/apps/$ApplicationId" $AppConfig

}


<#
.SYNOPSIS
 Removes an inactive application

.DESCRIPTION
 Removes an inactive application. Optionally disables an active application first if
 -Force parameter is supplied.

.PARAMETER ApplicationId
 ID of an app

.PARAMETER Force
 Force removal by deactivating app before removing

.LINK https://developer.okta.com/docs/reference/api/apps/#delete-application

#>
function Remove-OktaApp {

    [CmdletBinding( SupportsShouldProcess, ConfirmImpact='High' )]
    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'AppId' )]
        [string[]]
        $ApplicationId,

        [switch]
        $Force

    )

    process {

        $ApplicationId | ForEach-Object {

            $App = Get-OktaApp $ApplicationId

            if ( -not $Force -and $App.status -eq 'ACTIVE' ) {

                throw ( 'Cannot delete app ''{0}'', application is still active.' -f $App.label )

            }

            if ( $PSCmdlet.ShouldProcess( $App.label, 'delete' ) ) {

                Disable-OktaApp $ApplicationId -Confirm:$false
                
                Invoke-OktaMethod Delete "/api/v1/apps/$_"

            }

        }

    }

}


<#
.SYNOPSIS
 Activates an inactive application

.DESCRIPTION
 Activates an inactive application

.PARAMETER ApplicationId
 ID of an app to activate

.LINK https://developer.okta.com/docs/reference/api/apps/#activate-application

#>
function Enable-OktaApp {

    [CmdletBinding( SupportsShouldProcess, ConfirmImpact='Low' )]
    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'AppId' )]
        [string[]]
        $ApplicationId

    )

    process {

        $ApplicationId | ForEach-Object {

            $App = Get-OktaApp $ApplicationId

            if ( $App.status -eq 'ACTIVE' ) {

                Write-Warning ( 'Application {0} ({1}) is already active.' -f $App.label, $App.id )
                return

            }

            if ( $PSCmdlet.ShouldProcess( $App.label, 'activate' ) ) {
                
                Invoke-OktaMethod POST "/api/v1/apps/$_/lifecycle/activate"

            }

        }

    }

}


<#
.SYNOPSIS
 Deactivates an active application

.DESCRIPTION
 Deactivates an active application

.PARAMETER ApplicationId
 ID of an app to deactivate

.LINK https://developer.okta.com/docs/reference/api/apps/#deactivate-application

#>
function Disable-OktaApp {

    [CmdletBinding( SupportsShouldProcess, ConfirmImpact='High' )]
    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'AppId' )]
        [string[]]
        $ApplicationId

    )

    process {

        $ApplicationId | ForEach-Object {

            $App = Get-OktaApp $ApplicationId

            if ( $App.status -eq 'INACTIVE' ) {

                Write-Warning ( 'Application {0} ({1}) is already inactive.' -f $App.label, $App.id )
                return

            }

            if ( $PSCmdlet.ShouldProcess( $App.label, 'deactivate' ) ) {
                
                Invoke-OktaMethod POST "/api/v1/apps/$_/lifecycle/deactivate"

            }

        }

    }

}


<#
.SYNOPSIS
 Assigns a user to an application for SSO

.DESCRIPTION
 Assigns a user with or without a profile to an application for SSO. Note that
 the credential requirements are based on the SignOn Modes and Authentication
 Schemes of the application.

.PARAMETER ApplicationId
 ID of an app

.PARAMETER AppUser
 User's profile and credentials for the app

.EXAMPLE
 $Me = Get-OktaUser -id me
 $BookmarkApp = Find-OktaApps -Query 'Sample Bookmark App' -First 1
 Add-OktaAppUser $BookmarkApp.id @{ id=$Me.id; scope='USER' }

.LINK https://developer.okta.com/docs/reference/api/apps/#assign-user-to-application-for-sso
.LINK https://developer.okta.com/docs/reference/api/apps/#assign-user-to-application-for-sso-and-provisioning

#>
function Add-OktaAppUser {

    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'AppId' )]
        [string[]]
        $ApplicationId,

        [Parameter( Mandatory, Position=2 )]
        [pscustomobject[]]
        $AppUser

    )

    process {

        foreach ( $AppId in $ApplicationId ) {

            $App = Get-OktaApp $AppId

            for ( $i = 0; $i -lt $AppUser.Count; $i ++ ) {

                Write-Progress -Activity ( 'Assigning users to app {0} ({1})' -f $App.label, $App.id ) -Status ( 'Processing {0}...' -f $AppUser[$i].id ) -PercentComplete ( $i / $AppUser.Count * 100 )

                Invoke-OktaMethod POST "/api/v1/apps/$AppId/users" $AppUser[$i]

            }

            Write-Progress -Activity ( 'Assigning users to app {0} ({1})' -f $App.label, $App.id ) -Completed

        }

    }

}


<#
.SYNOPSIS
 Fetches a specific user assignment for an application by *id*

.DESCRIPTION
 Fetches a specific user assignment for an application by *id*

.PARAMETER ApplicationId
 ID of an app

.PARAMETER UserId
 Unique key of assigned User

.EXAMPLE
 $Me = Get-OktaUser -id me
 $BookmarkApp = Find-OktaApps -Query 'Sample Bookmark App' -First 1
 Get-OktaAppUser $BookmarkApp.id $Me.id

.LINK https://developer.okta.com/docs/reference/api/apps/#get-assigned-user-for-application

#>
function Get-OktaAppUser {

    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'AppId' )]
        [string[]]
        $ApplicationId,

        [Parameter( Mandatory, Position=2 )]
        [Alias( 'UId' )]
        [string[]]
        $UserId

    )

    process {

        foreach ( $AppId in $ApplicationId ) {

            foreach ( $UId in $UserId ) {

                Invoke-OktaMethod Get "/api/v1/apps/$AppId/users/$UId"

            }

        }

    }

}


<#
.SYNOPSIS
 Enumerates all assigned Application users for an application

.DESCRIPTION
 Enumerates all assigned Application users for an application with pagination.
 A subset of apps can be returned that match a supported filter expression or query.

.PARAMETER ApplicationId
 ID of an app

.PARAMETER After
 Specifies the pagination cursor for the next page of assignments

.PARAMETER Limit
 Specifies the number of results per page (maximum 500)

.PARAMETER Query
 Returns a filtered list of app users. The value of -Query is matched against an
 application user profile's *userName*, *firstName*, *lastName*, and *email*.

 Note that if that appliation profile does not include the attributes above you
 cannot search against them.

.PARAMETER All
 Return all results.

.PARAMETER First
 Return first N results.
 
.NOTES
 This operation only supports *startsWith* that matches what the string starts
 with to the query.

.LINK https://developer.okta.com/docs/reference/api/apps/#list-users-assigned-to-application

#>
function Find-OktaAppUsers {

    [CmdletBinding( DefaultParameterSetName='Default' )]
    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'AppId' )]
        [string[]]
        $ApplicationId,

        [string]
        $After,

        [ValidateRange( 1, 500 )]
        [int]
        $Limit = 50,

        [string]
        $Query,

        [Parameter( Mandatory, ParameterSetName='All' )]
        [switch]
        $All,

        [Parameter( Mandatory, ParameterSetName='First' )]
        [int]
        $First

    )

    process {

        foreach ( $AppId in $ApplicationId ) {

            $ParamSplat = @{}
        
            switch ( $PSCmdlet.ParameterSetName ) {
        
                'All' { $ParamSplat.All = $All }
        
                'First' {
        
                    $ParamSplat.First = $First
                    $Limit = [math]::Min( $First, 500 )
        
                }
        
            }
        
            $Path = "/api/v1/apps/$AppId/users?after=$After&limit=$Limit&q=$Query"
            
            Invoke-OktaPagedMethod $Path @ParamSplat

        }

    }
    
}


<#
.SYNOPSIS
 Updates a user's profile or credentials for an assigned application

.DESCRIPTION
 Updates a user's profile or credentials for an assigned application

.PARAMETER ApplicationId
 ID of an app

.PARAMETER UserId
 unique key of a valid User

.PARAMETER AppUser
 user's profile or credentials for app

.LINK https://developer.okta.com/docs/reference/api/apps/#update-application-credentials-for-assigned-user
.LINK https://developer.okta.com/docs/reference/api/apps/#update-application-profile-for-assigned-user

#>
function Set-OktaAppUser {

    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'AppId' )]
        [string[]]
        $ApplicationId,

        [Parameter( Mandatory, Position=2 )]
        [Alias( 'UId' )]
        [string]
        $UserId,

        [Parameter( Mandatory, Position=3 )]
        [pscustomobject]
        $AppUser

    )

    process {

        foreach ( $AppId in $ApplicationId ) {

            Invoke-OktaMethod POST "/api/v1/apps/$AppId/users/$UserId" $AppUser

        }

    }

}


<#
.SYNOPSIS
 Removes an assignment for a user from an application

.DESCRIPTION
 Removes an assignment for a user from an applications.
 
 For directories like Active Directory and LDAP, they act as the owner of the
 user's credential with Okta delegating authentication (DelAuth) to that
 directory. If this request is made for a user when DelAuth is enabled, then
 the user will be in a state with no password. You can then reset the user's
 password.

.PARAMETER ApplicationId
 ID of an app

.PARAMETER UserId
 Unique key of assigned User

.EXAMPLE
 $Me = Get-OktaUser -id me
 $BookmarkApp = Find-OktaApps -Query 'Sample Bookmark App' -First 1
 Remove-OktaAppUser $BookmarkApp.id $Me.id

.LINK https://developer.okta.com/docs/reference/api/apps/#remove-user-from-application

#>
function Remove-OktaAppUser {

    [CmdletBinding( SupportsShouldProcess, ConfirmImpact='High' )]
    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'AppId' )]
        [string[]]
        $ApplicationId,

        [Parameter( Mandatory, Position=2 )]
        [Alias( 'UId' )]
        [string[]]
        $UserId

    )

    process {

        foreach ( $AppId in $ApplicationId ) {

            $App = Get-OktaApp $AppId

            foreach ( $UId in $UserId ) {

                $AppUser = Get-OktaAppUser $AppId $UId |
                    Get-OktaUser

                $VerboseMessage = 'Deleting user {0} ({1}) from the {2} app...' `
                    -f $AppUser.profile.displayName, $AppUser.profile.login, $App.label

                $WarningMessage = 'Delete user {0} ({1}) from the {2} app?' `
                    -f $AppUser.profile.displayName, $AppUser.profile.login, $App.label
    
                if ( $PSCmdlet.ShouldProcess( $VerboseMessage, $WarningMessage, $null ) ) {
                    
                    Invoke-OktaMethod Delete "/api/v1/apps/$AppId/users/$UId"
    
                }

            }

        }

    }

}


<#
.SYNOPSIS
 Assigns a group to an application

.DESCRIPTION
 Assigns a group to an application

.PARAMETER ApplicationId
 ID of an app

.PARAMETER GroupId
 Unique key of a valid Group

.EXAMPLE
 $Group = ( Find-OktaGroup -Query 'Bookmark Users' ).Objects[0]
 $BookmarkApp = Find-OktaApps -Query 'Sample Bookmark App' -First 1
 Add-OktaAppUser $BookmarkApp.id @{ id=$Me.id; scope='USER' }

.LINK https://developer.okta.com/docs/reference/api/apps/#assign-user-to-application-for-sso
.LINK https://developer.okta.com/docs/reference/api/apps/#assign-user-to-application-for-sso-and-provisioning

#>
function Add-OktaAppGroup {

    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'AppId' )]
        [string[]]
        $ApplicationId,

        [Parameter( Mandatory, Position=2 )]
        [Alias( 'GId' )]
        [string[]]
        $GroupId

    )

    process {

        foreach ( $AppId in $ApplicationId ) {

            $App = Get-OktaApp $AppId

            for ( $i = 0; $i -lt $GroupId.Count; $i ++ ) {

                $Group = Get-OktaGroup $GroupId[$i]

                Write-Progress -Activity ( 'Assigning groups to app {0} ({1})' -f $App.label, $App.id ) -Status ( 'Processing {0}...' -f $Group.profile.name ) -PercentComplete ( $i / $GroupId.Count * 100 )

                Invoke-OktaMethod Put "/api/v1/apps/$AppId/groups/$($Group.id)" @{}

            }

            Write-Progress -Activity ( 'Assigning groups to app {0} ({1})' -f $App.label, $App.id ) -Completed

        }

    }

}


<#
.SYNOPSIS
 Fetches an application group assignment

.DESCRIPTION
 Fetches an application group assignment

.PARAMETER ApplicationId
 ID of an app

.PARAMETER GroupId
 Unique key of an assigned Group

.EXAMPLE
 $Groups = Find-OktaGroups -Query bookmark
 $BookmarkApp = Find-OktaApps -Query 'Sample Bookmark App' -First 1
 Get-OktaAppGroup $BookmarkApp.id $Group.id

.LINK https://developer.okta.com/docs/reference/api/apps/#get-assigned-user-for-application

#>
function Get-OktaAppGroup {

    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'AppId' )]
        [string[]]
        $ApplicationId,

        [Parameter( Mandatory, Position=2 )]
        [Alias( 'GId' )]
        [string[]]
        $GroupId

    )

    process {

        foreach ( $AppId in $ApplicationId ) {

            foreach ( $GId in $GroupId ) {

                Invoke-OktaMethod Get "/api/v1/apps/$AppId/groups/$GId"

            }

        }

    }

}


<#
.SYNOPSIS
 Enumerates group assignments for an application
.DESCRIPTION
 Enumerates group assignments for an application with pagination.

.PARAMETER ApplicationId
 ID of an app

.PARAMETER After
 Specifies the pagination cursor for the next page of assignments

.PARAMETER Limit
 Specifies the number of results per page (maximum 200)

.PARAMETER All
 Return all results.

.PARAMETER First
 Return first N results.

.EXAMPLE
 $BookmarkApp = Find-OktaApps -Query 'Sample Bookmark App' -First 1
 Find-OktaAppGroups $BookmarkApp.id
 
.NOTES
 The API doesn't return the Group name/label with the results, so you are only
 going to get back a list of GroupIds.

.LINK https://developer.okta.com/docs/reference/api/apps/#list-users-assigned-to-application

#>
function Find-OktaAppGroups {

    [CmdletBinding( DefaultParameterSetName='Default' )]
    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'AppId' )]
        [string[]]
        $ApplicationId,

        [string]
        $After,

        [ValidateRange( 1, 200 )]
        [int]
        $Limit = 20,

        [Parameter( Mandatory, ParameterSetName='All' )]
        [switch]
        $All,

        [Parameter( Mandatory, ParameterSetName='First' )]
        [int]
        $First

    )

    process {

        foreach ( $AppId in $ApplicationId ) {

            $ParamSplat = @{}
        
            switch ( $PSCmdlet.ParameterSetName ) {
        
                'All' { $ParamSplat.All = $All }
        
                'First' {
        
                    $ParamSplat.First = $First
                    $Limit = [math]::Min( $First, 200 )
        
                }
        
            }
        
            $Path = "/api/v1/apps/$AppId/groups?after=$After&limit=$Limit"
            
            Invoke-OktaPagedMethod $Path @ParamSplat

        }

    }
    
}


<#
.SYNOPSIS
 Removes a group assignment from an application

.DESCRIPTION
 Removes a group assignment from an application

.PARAMETER ApplicationId
 ID of an app

.PARAMETER GroupId
 Unique key of assigned Group

.EXAMPLE
 $BookmarkApp = Find-OktaApps -Query 'Sample Bookmark App' -First 1
 $BookmarkAppGroups = Find-OktaAppGroups $BookmarkApp.id
 Remove-OktaAppGroup $BookmarkApp.id $BookmarkAppGroups.id

.LINK https://developer.okta.com/docs/reference/api/apps/#remove-user-from-application

#>
function Remove-OktaAppGroup {

    [CmdletBinding( SupportsShouldProcess, ConfirmImpact='High' )]
    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'AppId' )]
        [string[]]
        $ApplicationId,

        [Parameter( Mandatory, Position=2 )]
        [Alias( 'GId' )]
        [string[]]
        $GroupId

    )

    process {

        foreach ( $AppId in $ApplicationId ) {

            $App = Get-OktaApp $AppId

            foreach ( $GId in $GroupId ) {

                $AppGroup = Get-OktaAppGroup $AppId $GId |
                    Get-OktaGroup

                $VerboseMessage = 'Deleting group {0} ({1}) from the {2} app...' `
                    -f $AppGroup.profile.name, $AppGroup.id, $App.label

                $WarningMessage = 'Delete group {0} ({1}) from the {2} app?' `
                    -f $AppGroup.profile.name, $AppGroup.id, $App.label
    
                if ( $PSCmdlet.ShouldProcess( $VerboseMessage, $WarningMessage, $null ) ) {
                    
                    Invoke-OktaMethod Delete "/api/v1/apps/$AppId/groups/$GId"
    
                }

            }

        }

    }

}

#endregion Apps

#region Events - https://developer.okta.com/docs/reference/api/events

function Get-OktaEvents($startDate, $filter, $limit = 1000, $url = "/api/v1/events?startDate=$startDate&filter=$filter&limit=$limit", $paged = $false) {
    if ($paged) {
        Invoke-OktaPagedMethod $url
    } else {
        Invoke-OktaMethod GET $url
    }
}
#endregion

#region Factors (MFA) - https://developer.okta.com/docs/reference/api/factors

function Get-OktaFactor($userid, $factorid) {
    Invoke-OktaMethod GET "/api/v1/users/$userid/factors/$factorid"
}

function Get-OktaFactors($userid) {
    Invoke-OktaMethod GET "/api/v1/users/$userid/factors"
}

function Get-OktaFactorsToEnroll($userid) {
    Invoke-OktaMethod GET "/api/v1/users/$userid/factors/catalog"
}

function Set-OktaFactor($userid, $factor, $activate = $false) {
    Invoke-OktaMethod POST "/api/v1/users/$userid/factors?activate=$activate" $factor
}

function Enable-OktaFactor($userid, $factorid, $body) {
    Invoke-OktaMethod POST "/api/v1/users/$userid/factors/$factorid/lifecycle/activate" $body
}

function Remove-OktaFactor($userid, $factorid) {
    $null = Invoke-OktaMethod DELETE "/api/v1/users/$userid/factors/$factorid"
}
#endregion

#region Groups - https://developer.okta.com/docs/reference/api/groups


<#
.SYNOPSIS
 Adds a new Group with OKTA_GROUP type to your organization

.DESCRIPTION
 Adds a new Group with OKTA_GROUP type to your organization

.PARAMETER GroupProfile
 Profile for a new Group

.LINK https://developer.okta.com/docs/reference/api/groups/#add-group
.LINK https://developer.okta.com/docs/reference/api/groups/#profile-object

#>
function New-OktaGroup {

    param(
    
        [Parameter( Mandatory, Position=1 )]
        [hashtable[]]
        $GroupProfile
    
    )

    process {

        $GroupProfile | ForEach-Object {

            Invoke-OktaMethod POST '/api/v1/groups' $_

        }

    }
    
}


<#
.SYNOPSIS
 Fetches a specific Group by id from your organization

.DESCRIPTION
 Fetches a specific Group by id from your organization
 
.PARAMETER Id
 ID of a Group

.LINK https://developer.okta.com/docs/reference/api/groups/#get-group

#>
function Get-OktaGroup {

    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'GroupId', 'GId' )]
        [string[]]
        $Id

    )

    process {

        $Id | ForEach-Object {

            Invoke-OktaMethod GET "/api/v1/groups/$_"

        }

    }

}


<#
.SYNOPSIS
 Enumerates Groups in your organization with pagination

.DESCRIPTION
 Enumerates Groups in your organization with pagination.
 A subset of Groups can be returned that match a supported filter expression or query.

.PARAMETER After
 Specifies the pagination cursor for the next page of Groups

.PARAMETER Limit
 Specifies the number of Group results in a page

.PARAMETER Query
 Searches the *name* property of Groups for matching value

.PARAMETER Filter
 Filter expression for Groups

.PARAMETER All
 Return all results.

.PARAMETER First
 Return first N results.
 
.NOTES
 This operation only supports *startsWith* that matches what the string starts
 with to the query.

.LINK https://developer.okta.com/docs/reference/api/groups/#list-groups
.LINK https://developer.okta.com/docs/reference/api-overview/#filtering

#>
function Find-OktaGroups {

    [CmdletBinding( DefaultParameterSetName='Default' )]
    param(

        [string]
        $After,

        [ValidateRange( 1, 200 )]
        [int]
        $Limit = 10,

        [string]
        $Query,

        [string]
        $Filter,

        [Parameter( Mandatory, ParameterSetName='All' )]
        [switch]
        $All,

        [Parameter( Mandatory, ParameterSetName='First' )]
        [int]
        $First

    )
    
    $ParamSplat = @{}
        
    switch ( $PSCmdlet.ParameterSetName ) {

        'All' { $ParamSplat.All = $All }

        'First' {

            $ParamSplat.First = $First
            $Limit = [math]::Min( $First, 200 )

        }

    }

    $Path = '/api/v1/groups?'

    if ( $After ) { $Path += "after=$After&" }
    if ( $Limit ) { $Path += "limit=$Limit&" }

    if ( $Query ) {
        
        $Path += "q=$( [System.Web.HttpUtility]::UrlEncode( $Query  ) )&"
    
    } elseif ( $Filter ) {
        
        $Path += "filter=$( [System.Web.HttpUtility]::UrlEncode( $Filter ) )&"
    
    }

    Invoke-OktaPagedMethod $Path @ParamSplat
    
}


<#
.SYNOPSIS
 Updates the Profile for a Group with OKTA_GROUP type from your organization

.DESCRIPTION
 Updates the Profile for a Group with OKTA_GROUP type from your organization

.PARAMETER Id
 ID of the Group to update

.PARAMETER GroupProfile
 Updated Profile for the Group

.NOTES
 All Profile properties must be specified when updating a Groups's Profile.
 Partial updates aren't supported.

.LINK https://developer.okta.com/docs/reference/api/groups/#update-group
.LINK https://developer.okta.com/docs/reference/api/groups/#profile-object

#>
function Set-OktaGroup {

    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'GroupId', 'GId' )]
        [string[]]
        $Id,
    
        [Parameter( Mandatory, Position=2 )]
        [hashtable]
        $GroupProfile

    )

    process {

        $Id | ForEach-Object {

            Invoke-OktaMethod PUT "/api/v1/groups/$_" $GroupProfile

        }

    }

}


<#
.SYNOPSIS
 Removes a Group with OKTA_GROUP or APP_GROUP type from your organization

.DESCRIPTION
 Removes a Group with OKTA_GROUP or APP_GROUP type from your organization

.PARAMETER Id
 ID of the Group to delete
#>
function Remove-OktaGroup {

    [CmdletBinding( SupportsShouldProcess, ConfirmImpact='High' )]
    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'GroupId', 'GId' )]
        [string[]]
        $Id

    )

    process {

        Get-OktaGroup $Id | ForEach-Object {

            if ( $PSCmdlet.ShouldProcess( $_.profile.name, 'delete' ) ) {

                Invoke-OktaMethod DELETE "/api/v1/groups/$($_.id)"

            }

        }

    }

}

<#
.SYNOPSIS
 Enumerates all users that are a member of a Group

.DESCRIPTION
 Enumerates all users that are a member of a Group

.PARAMETER Id
 ID of the Group

.PARAMETER After
 Specifies the pagination cursor for the next page of assignments

.PARAMETER Limit
 Specifies the number of results per page (maximum 200)

.PARAMETER All
 Return all results.

.PARAMETER First
 Return first N results.

#>
function Find-OktaGroupMembers {

    [CmdletBinding( DefaultParameterSetName='Default' )]
    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'GroupId', 'GId' )]
        [string[]]
        $Id,

        [string]
        $After,

        [ValidateRange( 1, 1000 )]
        [int]
        $Limit = 200,

        [Parameter( Mandatory, ParameterSetName='All' )]
        [switch]
        $All,

        [Parameter( Mandatory, ParameterSetName='First' )]
        [int]
        $First

    )

    process {

        foreach ( $GroupId in $Id ) {

            $ParamSplat = @{}
        
            switch ( $PSCmdlet.ParameterSetName ) {
        
                'All' { $ParamSplat.All = $All }
        
                'First' {
        
                    $ParamSplat.First = $First
                    $Limit = [math]::Min( $First, 1000 )
        
                }
        
            }
        
            $Path = "/api/v1/groups/$GroupId/users?after=$After&limit=$Limit"
            
            Invoke-OktaPagedMethod $Path @ParamSplat

        }

    }


}


<#
.SYNOPSIS
 Adds a user to a Group with OKTA_GROUP type

.DESCRIPTION
 Adds a user to a Group with OKTA_GROUP type

.PARAMETER Id
 ID of the Group

.PARAMETER UserId
 ID of a User

.LINK https://developer.okta.com/docs/reference/api/groups/#add-user-to-group

#>
function Add-OktaGroupMember {

    [CmdletBinding( SupportsShouldProcess, ConfirmImpact='Low' )]
    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'GroupId', 'GId' )]
        [string[]]
        $Id,

        [Parameter( Mandatory, Position=2 )]
        [pscustomobject[]]
        $UserId

    )

    process {

        # save some API calls if we are not confirming
        if ( $ConfirmPreference -ne [System.Management.Automation.ConfirmImpact]::Low ) {

            foreach ( $GroupId in $Id ) {

                $UserId | ForEach-Object {

                    $null = Invoke-OktaRestMethod PUT "/api/v1/groups/$GroupId/users/$_"

                }
            
            }

        # if we are confirming lookup the group and users for confirmation
        } else {

            Get-OktaGroup $Id -PipelineVariable 'Group' | ForEach-Object {

                $ConfirmMessage = 'add to {0}' -f $Group.profile.name

                Get-OktaUser $UserId | ForEach-Object {

                    $UserName = '{0} ({1})' -f $_.profile.displayName, $_.profile.login

                    if ( $PSCmdlet.ShouldProcess( $UserName, $ConfirmMessage ) ) {

                        $null = Invoke-OktaRestMethod PUT "/api/v1/groups/$GroupId/users/$_"

                    }

                }

            }
        }

    }

}


<#
.SYNOPSIS
 Removes a user from a Group with OKTA_GROUP type

.DESCRIPTION
 Removes a user from a Group with OKTA_GROUP type

.PARAMETER Id
 ID of the Group

.PARAMETER UserId
 ID of a User

.LINK https://developer.okta.com/docs/reference/api/groups/#remove-user-from-group

#>
function Remove-OktaGroupMember {

    [CmdletBinding( SupportsShouldProcess, ConfirmImpact='High' )]
    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'GroupId', 'GId' )]
        [string[]]
        $Id,

        [Parameter( Mandatory, Position=2 )]
        [pscustomobject[]]
        $UserId

    )

    process {

        # save some API calls if we are not confirming
        if ( $ConfirmPreference -ne [System.Management.Automation.ConfirmImpact]::High ) {

            foreach ( $GroupId in $Id ) {

                $UserId | ForEach-Object {

                    $null = Invoke-OktaRestMethod DELETE "/api/v1/groups/$GroupId/users/$_"

                }
            
            }

        # if we are confirming lookup the group and users for confirmation
        } else {

            Get-OktaGroup $Id -PipelineVariable 'Group' | ForEach-Object {

                $ConfirmMessage = 'remove from {0}' -f $Group.profile.name

                Get-OktaUser $UserId | ForEach-Object {

                    $UserName = '{0} ({1})' -f $_.profile.displayName, $_.profile.login

                    if ( $PSCmdlet.ShouldProcess( $UserName, $ConfirmMessage ) ) {

                        $null = Invoke-OktaRestMethod DELETE "/api/v1/groups/$GroupId/users/$_"

                    }

                }

            }
        }

    }

}

function New-OktaGroupRule($groupRule) {
    Invoke-OktaMethod POST "/api/v1/groups/rules" $groupRule
}

function Get-OktaGroupApps($id, $limit = 20, $url = "/api/v1/groups/$id/apps?limit=$limit") {
    Invoke-OktaPagedMethod $url
}

function Get-OktaGroupRules($limit = 50, $url = "/api/v1/groups/rules?limit=$limit") {
    Invoke-OktaPagedMethod $url
}

function Enable-OktaGroupRule($ruleid) {
    Invoke-OktaMethod POST "/api/v1/groups/rules/$ruleid/lifecycle/activate"
}
#endregion

#region IdPs - https://developer.okta.com/docs/reference/api/idps

function Get-OktaIdps($q, $type, $limit = 20, $url = "/api/v1/idps?q=$q&type=$type&limit=$limit") {
    Invoke-OktaPagedMethod $url
}
#endregion

#region Logs - https://developer.okta.com/docs/reference/api/system-log

function Get-OktaLogs($since, $until, $filter, $q, $sortOrder = "ASCENDING", $limit = 100, $url = "/api/v1/logs?since=$since&until=$until&filter=$filter&q=$q&sortOrder=$sortOrder&limit=$limit", $convert = $true) {
    Invoke-OktaPagedMethod $url $convert
}
#endregion

#region Roles - https://developer.okta.com/docs/reference/api/roles

function Get-OktaRoles($id) {
    Invoke-OktaMethod GET "/api/v1/users/$id/roles"
}
#endregion

#region Schemas - https://developer.okta.com/docs/reference/api/schemas

function New-OktaSchema($schema) {
    Invoke-OktaMethod POST "/api/v1/meta/schemas/user/default" $schema
}

function Get-OktaSchemas() {
    Invoke-OktaMethod GET "/api/v1/meta/schemas/user/default"
}
#endregion

#region Users - https://developer.okta.com/docs/reference/api/users

function New-OktaUser($user, $activate = $true) {
    Invoke-OktaMethod POST "/api/v1/users?activate=$activate" $user
}


<#
.SYNOPSIS
 Lists users in your organization with pagination in most cases

.DESCRIPTION
 Lists users in your organization with pagination in most cases.
 A subset of users can be returned that match a supported filter expression or search criteria.

.PARAMETER After
 Specifies the pagination cursor for the next page of users

.PARAMETER Limit
 Specifies the number of results returned (maximum 200)

.PARAMETER Query
 Finds a user that matches *firstName*, *lastName*, and *email* properties

.PARAMETER Search
 Searches for users with a supported filtering expression for most properties.
 Supported Properties: status, lastUpdated, id, profile.login, profile.email, profile.firstName, and profile.lastName

.PARAMETER SortBy
 Specifies field to sort by (for search queries only)

.PARAMETER SortOrder
 Specifies sort order asc or desc (for search queries only)

.PARAMETER All
 Return all results.

.PARAMETER First
 Return first N results.
 
.NOTES
 This operation only supports *startsWith* that matches what the string starts
 with to the query.

.LINK https://developer.okta.com/docs/reference/api/users/#list-users
.LINK https://developer.okta.com/docs/reference/api-overview/#filtering

#>
function Get-OktaUser {

    [CmdletBinding()]
    param(

        [Parameter( Mandatory, Position=1, ValueFromPipeline, ValueFromPipelineByPropertyName )]
        [Alias( 'Id', 'UId', 'Login' )]
        [string[]]
        $UserId

    )

    process {

        $UserId | ForEach-Object {

            Invoke-OktaMethod Get "/api/v1/users/$( [System.Web.HttpUtility]::UrlEncode( $_ ) )"

        }

    }

}


<#
.SYNOPSIS
 Lists users in your organization with pagination in most cases

.DESCRIPTION
 Lists users in your organization with pagination in most cases.
 A subset of users can be returned that match a supported filter expression or search criteria.

.PARAMETER After
 Specifies the pagination cursor for the next page of users

.PARAMETER Limit
 Specifies the number of results returned (maximum 200)

.PARAMETER Query
 Finds a user that matches *firstName*, *lastName*, and *email* properties

.PARAMETER Filter
Filters users with a supported expression for a subset of properties.
 Supported Properties: status, lastUpdated, id, profile.login, profile.email, profile.firstName, and profile.lastName

.PARAMETER Search
 Searches for users with a supported filtering expression for most properties.

.PARAMETER SortBy
 Specifies field to sort by (for search queries only)

.PARAMETER SortOrder
 Specifies sort order asc or desc (for search queries only)

.PARAMETER All
 Return all results.

.PARAMETER First
 Return first N results.
 
.NOTES
 This operation only supports *startsWith* that matches what the string starts
 with to the query.

.LINK https://developer.okta.com/docs/reference/api/users/#list-users
.LINK https://developer.okta.com/docs/reference/api-overview/#filtering

#>
function Find-OktaUsers {

    [CmdletBinding( DefaultParameterSetName='Default' )]
    param(

        [string]
        $After,

        [ValidateRange( 1, 200 )]
        [int]
        $Limit,

        [string]
        $Query,

        [string]
        $Filter,

        [string]
        $Search,

        [string]
        $SortBy,

        [ValidateSet( 'Ascending', 'Descending')]
        [string]
        $SortOrder,

        [Parameter( Mandatory, ParameterSetName='All' )]
        [switch]
        $All,

        [Parameter( Mandatory, ParameterSetName='First' )]
        [int]
        $First

    )
    
    $ParamSplat = @{}
        
    switch ( $PSCmdlet.ParameterSetName ) {

        'All' { $ParamSplat.All = $All }

        'First' {

            $ParamSplat.First = $First
            $Limit = [math]::Min( $First, 200 )

        }

    }

    $Path = '/api/v1/users?'

    if ( $After ) { $Path += "after=$After&" }
    if ( $Limit ) { $Path += "limit=$Limit&" }

    if ( $Query ) {
        
        $Path += "q=$( [System.Web.HttpUtility]::UrlEncode( $Query  ) )&"
    
    } elseif ( $Filter ) {
        
        $Path += "filter=$( [System.Web.HttpUtility]::UrlEncode( $Filter ) )&"
    
    } elseif ( $Search ) {

        $Path += "search=$( [System.Web.HttpUtility]::UrlEncode( $Search ) ) &"

        if ( $SortBy ) {

            $Path += "sortBy=$SortBy"

            if ( $SortOrder ) {

                $Path += 'sortOrder=' + ( 'asc', 'desc' )[ $SortOrder -eq 'Descending' ]
            }

        }

    }

    Invoke-OktaPagedMethod $Path @ParamSplat
    
}

function Set-OktaUser($id, $user) {
# Only the profile properties specified in the request will be modified when using the POST method.
    Invoke-OktaMethod POST "/api/v1/users/$id" $user
}

function Get-OktaUserAppLinks($id) {
    Invoke-OktaMethod GET "/api/v1/users/$id/appLinks"
}

function Get-OktaUserGroups($id, $limit = 200, $url = "/api/v1/users/$id/groups?limit=$limit", $paged = $false) {
    if ($paged) {
        Invoke-OktaPagedMethod $url
    } else {
        Invoke-OktaMethod GET $url
    }
}

function Enable-OktaUser($id, $sendEmail = $true) {
    Invoke-OktaMethod POST "/api/v1/users/$id/lifecycle/activate?sendEmail=$sendEmail"
}

function Disable-OktaUser($id) {
    $null = Invoke-OktaMethod POST "/api/v1/users/$id/lifecycle/deactivate"
}

function Set-OktaUserResetPassword($id, $sendEmail = $true) {
    Invoke-OktaMethod POST "/api/v1/users/$id/lifecycle/reset_password?sendEmail=$sendEmail"
}

function Set-OktaUserExpirePassword($id) {
    Invoke-OktaMethod POST "/api/v1/users/$id/lifecycle/expire_password"
}

function Set-OktaUserUnlocked($id) {
    Invoke-OktaMethod POST "/api/v1/users/$id/lifecycle/unlock"
}

function Remove-OktaUser($id) {
    $null = Invoke-OktaMethod DELETE "/api/v1/users/$id"
}
#endregion

#region Zones - https://developer.okta.com/docs/reference/api/zones

function New-OktaZone($zone) {
    Invoke-OktaMethod POST "/api/v1/zones" $zone
}

function Get-OktaZone($id) {
    Invoke-OktaMethod GET "/api/v1/zones/$id"
}

function Get-OktaZones($filter, $limit = 20, $url = "/api/v1/zones?filter=$filter&limit=$limit") {
    Invoke-OktaPagedMethod $url
}
#endregion

