$ipblock = ReadHost "Enter IP address to block"

WriteHost "Blocking"
New-NetFirewallRule -DisplayName "CCDC-Block $ipblock" -Action Block -RemoteAddress $ipblock
New-NetFirewallRule -DisplayName "CCDC-Block $ipblock" -Action Block -RemoteAddress $ipblock -Direction Outbound

ReadHost "Done. Press enter to exit..."
