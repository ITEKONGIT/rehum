param(
    [Parameter(Mandatory = $true, Position = 0)][string]$To,
    [Parameter(Mandatory = $true, Position = 1)][string]$Data,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$ExtraArgs
)

$ProjectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $ProjectDirectory
try {
    python -m evm_call_explainer $To $Data @ExtraArgs
}
finally {
    Pop-Location
}
