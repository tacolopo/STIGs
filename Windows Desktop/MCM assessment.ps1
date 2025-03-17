$outputFileName = "windows10_assessment_complete_data.txt"
$directoryPath = "\Win10Tier3"
#change to your username
$outputFilePath = "C:\"

#build one file from all the files
if (Test-Path -Path $directoryPath -PathType Container) {
	$textFiles = Get-ChildItem -Path $directoryPath -Filter "*.txt"
	if ($textFiles.Count -gt 0) {
		$combinedContent = $textFiles | Get-Content | Out-String
		$combinedContent | Out-File -FilePath (Join-Path $outputFilePath $outputFileName) -Encoding UTF8
	}
	else {
		Write-Host "Directory not found ):"
	}
}

#count all the stig occurrences
#change to your username
$filePath = "C:\windows10_assessment_complete_data.txt"

$content = Get-Content $filePath
$stringCount = @{}

foreach ($line in $content) {
	if ($line -match "^(FFOX|WN10|EDGE)-[A-Za-z0-9]{2}-\d{6}") {
		$match = $matches[0]
		if ($stringCount.ContainsKey($match)) {
			$stringCount[$match]++
		} else {
			$stringCount[$match] = 1
		}
	}
}

#make csv of stig occurrences
$sortedStrings = $stringCount.GetEnumerator() | Sort-Object Value -Descending
$csvData1 = $sortedStrings | Select-Object @{Name='STIG ID';Expression={$_.Key}}, @{Name='Count';Expression={$_.Value}}
$outputCsv1 = Join-Path -Path $outputFilePath -ChildPath "stig_occurrences_count.csv"
$csvData1 | Export-Csv -Path $outputCsv1 -NoTypeInformation

#second csv for each host
$fileSTIGCount = @{}
$files = Get-ChildItem -Path $directoryPath -File
foreach ($file in $files) {
	$fileContent = Get-Content $file.FullName
	$stigCount = 0
	
	foreach ($line in $fileContent) {
		if ($line -match "^(FFOX|WN10|EDGE)-\d{2}-\d{6}") {
			$stigCount++
		}
	}
	$fileNameWithoutExtension = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
	$fileSTIGCount[$fileNameWithoutExtension] = $stigCount
}

$sortedFiles = $fileSTIGCount.GetEnumerator() | Sort-Object Value -Descending

$csvData2 = $sortedFiles | ForEach-Object {
	[PSCustomObject]@{
		FileName = $_.Key
		STIGCount = $_.Value
	}
}

$outputCsv2 = Join-Path -Path $outputFilePath -ChildPath "stig_occurrences_by_host.csv"
$csvData2 | Export-Csv -Path $outputCsv2 -NoTypeInformation
