# -------------------------------------------------------------------------------------------------------
# Script: ConvertTo-GzipStream.ps1
# Last Edit: 09/03/2019 @ 1546
# https://www.github.com/gh0x0st
# Code snippet to convert a byte array into a compressed gzip stream
# --------------------------------------------------------------------------------------------------------
Function ConvertTo-GzipStream()
{
	[cmdletBinding()]
	Param (
		[byte[]]$ByteArray
	)
	Process
	{
        $MemoryStream = New-Object System.IO.MemoryStream
        $GzipStream = New-Object System.IO.Compression.GzipStream $MemoryStream, ([System.IO.Compression.CompressionMode]::Compress)
        $GzipStream.Write( $ByteArray, 0, $ByteArray.Length )
        $GzipStream.Close()
        $MemoryStream.Close()
        $Output = $MemoryStream.ToArray()
	}
	End
	{
		return $Output
	}
}