$candidates = "AppleInc.AppleDevices", "AppleInc.iTunes"

foreach ($candidate in $candidates) {
    $package = Get-AppxPackage $candidate
    if ($package) {
        # print
        Write-Host Found $package.Name $package.Version
        break
    }
}
