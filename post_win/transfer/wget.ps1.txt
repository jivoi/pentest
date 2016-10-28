if ($args.Length -lt 2){
    Write-Host "Usage: wget.ps1 <url> <outfile>"
    Exit
}

$url = $args[0]
$output = "$($pwd)\$($args[1])"

$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url, $output)
Exit
