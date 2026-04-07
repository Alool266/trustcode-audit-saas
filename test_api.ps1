# Test script for TrustCode AI API
$uri = "https://frontend-six-psi-78.vercel.app/api/audit"
$filePath = "test_audit_bad.py"

# Read the file content
$fileContent = Get-Content $filePath -Raw

# Create multipart form data
$boundary = [System.Guid]::NewGuid().ToString()
$LF = "`r`n"

# Build the body
$bodyBytes = @()
$bodyBytes += [System.Text.Encoding]::UTF8.GetBytes("--$boundary$LF")
$bodyBytes += [System.Text.Encoding]::UTF8.GetBytes("Content-Disposition: form-data; name=`"file`"; filename=`"test.py`"$LF")
$bodyBytes += [System.Text.Encoding]::UTF8.GetBytes("Content-Type: application/x-python$LF$LF")
$bodyBytes += [System.Text.Encoding]::UTF8.GetBytes($fileContent)
$bodyBytes += [System.Text.Encoding]::UTF8.GetBytes("$LF--$boundary--$LF")

# Combine all bytes
$fullBody = @()
foreach ($bytes in $bodyBytes) {
    $fullBody += $bytes
}

# Make the request
$headers = @{
    "Content-Type" = "multipart/form-data; boundary=$boundary"
}

try {
    $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $fullBody
    Write-Host "Success!" -ForegroundColor Green
    $response | ConvertTo-Json -Depth 10
} catch {
    Write-Host "Error: $_" -ForegroundColor Red
    Write-Host "Status Code: $($_.Exception.Response.StatusCode.value__)"
}
