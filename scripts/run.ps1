param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("single", "subset", "all")]
    [string]$data
)

# use different path depending on the data option
if ($data -eq "single") {
    $path = "data\single"
} elseif ($data -eq "subset") {
    $path = "data\subset"
} elseif ($data -eq "all") {
    $path = "data\all"
}

# run the script
python main.py -t $path