param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("small", "large")]
    [string]$size,
    [Parameter(Mandatory=$false)]
    [ValidateSet("validate")]
    [string]$validate
)

# use different path depending on the data option
if ($size -eq "small") {
    $path = "data\small"
} elseif ($size -eq "large") {
    $path = "data\large"
} else {
    Write-Host "Invalid size option"
    exit
} 

$training_dir = $path + "\training"
$validation_dir = $path + "\validation"

if ($validate -eq "validate") {
    python main.py -t $training_dir -v $validation_dir
} else {
    python main.py -t $training_dir
}