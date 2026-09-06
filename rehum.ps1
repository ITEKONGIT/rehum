param(
    [Parameter(Mandatory = $true, Position = 0)][string]$To,
    [Parameter(Mandatory = $true, Position = 1)][string]$Data,
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$ExtraArgs
)

$ProjectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $ProjectDirectory
try {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        python .\rehum.py $To $Data @ExtraArgs
    }
    elseif (Get-Command py -ErrorAction SilentlyContinue) {
        py -3 .\rehum.py $To $Data @ExtraArgs
    }
    else {
        throw "Python 3 was not found. Install Python 3.11 or newer."
    }
}
finally {
    Pop-Location
}
