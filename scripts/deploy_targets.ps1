[int]$num_targets = Read-Host "Enter number of targets to create"
$target_params = [PSCustomObject]@{
    CPU = 1
    MEM = "1G"
    DISK = "8G"
}

$jobs = @()

for ($i = 0; $i -lt $num_targets; $i++){
    $job = Start-Job -ScriptBlock {
        param($params, $index)
        $target = "target$index"
        multipass launch --name $target --cpus $params.CPU --memory $params.MEM --disk $params.DISK --network name=Ethernet,mode=auto

        Write-Output "Launch completed for $target"
    } -ArgumentList $target_params, $i
    $jobs += $job
}

Write-Host "Waiting for jobs to finish..."

$jobs | Wait-Job | Out-Null

Write-Host "All targets created. Receiving results..."

foreach ($job in $jobs) {
    Receive-Job -Job $job
    Remove-Job -Job $job
}

multipass list
Write-Host "Targets have been created."
