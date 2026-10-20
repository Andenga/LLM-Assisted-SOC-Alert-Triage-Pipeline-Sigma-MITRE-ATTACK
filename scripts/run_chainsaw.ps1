# scripts\run_chainsaw.ps1
$chainsaw = "C:\tools\chainsaw\chainsaw.exe"
& $chainsaw hunt data\raw\attack `
  -s C:\tools\sigma\rules\windows `
  --mapping C:\tools\chainsaw\mappings\sigma-event-logs-all.yml `
  --skip-errors --json -o data\alerts\attack_alerts.json