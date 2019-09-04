# -------------------------------------------------------------------------------------------------------
# Script: ConvertTo-EncodedGzipStream.ps1
# Last Edit: 09/03/2019 @ 1546
# https://www.github.com/gh0x0st
# Code snippet to encode a compressed gzip stream
# --------------------------------------------------------------------------------------------------------
Function ConvertTo-EncodedGzipStream()
{
	[cmdletBinding()]
	Param (
		[byte[]]$GzipStream
	)
	Process
	{  
        $Output = [System.Convert]::ToBase64String($GzipStream)
	}
	End
	{
		return $Output
	}
}