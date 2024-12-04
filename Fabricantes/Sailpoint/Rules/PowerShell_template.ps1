###############################################################################################################################
# SETUP
# Instructions (for each IQService host that could run the script):
#   - Update the path to Utils.dll (can be an unqualified path like "Utils.dll" since script is copied to IQService folder for execution)
#   - Make sure Utils.dll is in the specified folder on each IQService host
#   - Be sure the account that runs IQService has appropriate permissions to create directories and set permissions on them
#   - Be sure to set the "run as" account for the IQService in Windows Service to the above-specified account instead of just the "logged on" user
#   - Set a proper location for the $logFile variable
#   - Set the $enableDebug flag to $true or $false to toggle debug mode
###############################################################################################################################

param (
 [Parameter(Mandatory=$true)][System.String]$requestString
)

#include SailPoint library
Add-Type -Path "c:\SailPoint\IQService\Utils.dll";

#import AD cmdlets
Import-Module activeDirectory

#log file info
$logDate = Get-Date -UFormat "%Y%m%d"
$logFile = "c:\SailPoint\Scripts\Logs\SampleSourceBeforeCreateScript_$logDate.log"
$enableDebug = $false

###############################################################################################################################
# HELPER FUNCTIONS
###############################################################################################################################

#save logging files to a separate txt file
function LogToFile([String] $info) {
    $info | Out-File $logFile -Append
}

#if we have a non-null account request, get our value; otherwise return nothing
function Get-AttributeValueFromAccountRequest([sailpoint.Utils.objects.AccountRequest] $request, [String] $targetAttribute) {
    $value = $null;

    if ($request) {
        foreach ($attrib in $request.AttributeRequests) {
            if ($attrib.Name -eq $targetAttribute) {
                $value = $attrib.Value;
                break;
            }
        }
    } else {
        LogToFile("Account request object was null");
    }
    return $value;
}


###############################################################################################################################
# BODY
###############################################################################################################################
if($enableDebug) {
    LogToFile("Entering beforeScript")
}

try {

    ##########################
    # Begin SailPoint protected code -- do not modify this code block
    #
        $sReader = New-Object System.IO.StringReader([System.String]$env:Request);
        $xmlReader = [System.xml.XmlTextReader]([sailpoint.utils.xml.XmlUtil]::getReader($sReader));
        $requestObject = New-Object Sailpoint.Utils.objects.AccountRequest($xmlReader);

        #debug line for testing
        if($enableDebug) {
            LogToFile("Request object contents:")
            LogToFile($requestObject | Out-String)
        }
    #
    # End SailPoint protected code
    ##########################


    ##########################
    # Begin Client-provided code

    #get the necessary info we need from the accountRequest object
    #as an example: $nativeIdentity = $requestObject.nativeIdentity

    #do whatever work needs to be done here

    #
    # End Client-provided code
}
catch {
    $ErrorMessage = $_.Exception.Message
   $ErrorItem = $_.Exception.ItemName
   LogToFile("Error: Item = $ErrorItem -> Message = $ErrorMessage")
}

if($enableDebug) {
    LogToFile("Exiting beforeScript")
}