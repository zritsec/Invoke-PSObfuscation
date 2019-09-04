# -------------------------------------------------------------------------------------------------------
# Script: ConvertTo-ByteArray.ps1
# Last Edit: 09/03/2019 @ 1546
# https://www.github.com/gh0x0st
# Code snippet to convert strings or the contents of files to a byte array
# --------------------------------------------------------------------------------------------------------
Function ConvertTo-ByteArray()
{
	[cmdletBinding()]
	Param (
		[Parameter(Position = 0, Mandatory = $false, ParameterSetName = 'String')]
		[System.String]$String,
		[Parameter(Position = 1, Mandatory = $false, ParameterSetName = 'File Content')]
		[ValidateScript({ Test-Path $_ })]
		[System.String]$Path
	)
	Process
	{
        switch ($PsCmdlet.ParameterSetName)
        {
            "String" {$Content = $String}
            "File Content" {$Content = [System.IO.File]::ReadAllLines( ( Resolve-Path $Path ) )}
        }
		$Encoding = [System.Text.Encoding]::ASCII
		$Output = $Encoding.GetBytes($Content)
	}
	End
	{
		return $Output
	}
}