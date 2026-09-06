param(
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$ExtraArgs
)

$ProjectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $ProjectDirectory
try {
    python -m evm_call_explainer.preflight @ExtraArgs
}
finally {
    Pop-Location
}
