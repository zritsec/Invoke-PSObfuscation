# -------------------------------------------------------------------------------------------------------
# Script: ConvertTo-EncodedDecoder.ps1
# Last Edit: 09/03/2019 @ 1546
# https://www.github.com/gh0x0st
# Code snippet to encode the decoder function for the encoded, compressed gzip stream
# --------------------------------------------------------------------------------------------------------
Function ConvertTo-EncodedDecoder()
{
	[cmdletBinding()]
	Param (
		[System.String]$EncodedGzipStream
	)
	Process
	{
		[System.String]$Decoder = '$Decoded = [System.Convert]::FromBase64String("<Base64>");$ms = (New-Object System.IO.MemoryStream($Decoded,0,$Decoded.Length));iex(New-Object System.IO.StreamReader(New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress))).readtoend()'
		[System.String]$Decoder = $Decoder -replace "<Base64>", "$EncodedGzipStream"
		[byte[]]$bytes = [System.Text.Encoding]::Unicode.GetBytes($Decoder)
		[System.String]$Output = [Convert]::ToBase64String($bytes)
	}
	End
	{
		return $Output
	}
}