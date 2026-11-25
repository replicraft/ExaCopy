# The release producer emits a classic, stored ZIP containing exactly the
# three raw offline bundle members. Read just the fixed records and copy
# their data into newly created files under installer-selected names.
function Read-ExaCopyReleaseArchiveEntries {
    param([IO.Stream] $Archive)

    $endRecordSize = 22
    $directoryHeaderSize = 46
    $localHeaderSize = 30
    $limits = @{
        'release.manifest' = $ExaCopyManifestLimit
        'release.sig' = $ExaCopySignatureLimit
        'exacopy.exe' = $ExaCopyArtifactLimit
    }
    $expected = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $expectedSize = $limits.Count * $directoryHeaderSize
    foreach ($name in $limits.Keys) {
        [void]$expected.Add($name)
        $expectedSize += $name.Length
    }
    if ($Archive.Length -lt ($endRecordSize + $expectedSize) -or $Archive.Length -gt $ExaCopyReleaseZipLimit) {
        throw 'Release ZIP is outside its byte limits.'
    }
    $reader = [IO.BinaryReader]::new($Archive, [Text.Encoding]::ASCII, $true)
    try {
        $endRecord = $Archive.Length - $endRecordSize
        $Archive.Position = $endRecord
        if ($reader.ReadUInt32() -ne 0x06054b50 -or $reader.ReadUInt32() -ne 0 -or
            $reader.ReadUInt16() -ne $limits.Count -or $reader.ReadUInt16() -ne $limits.Count -or
            $reader.ReadUInt32() -ne $expectedSize) {
            throw 'Release ZIP must have one disk and the exact three classic directory records.'
        }
        $directoryOffset = [long]$reader.ReadUInt32()
        if ($reader.ReadUInt16() -ne 0 -or $directoryOffset -ne $endRecord - $expectedSize) {
            throw 'Release ZIP has an invalid directory offset or archive comment.'
        }

        $Archive.Position = $directoryOffset
        $nextLocal = 0L
        $members = [ordered]@{}
        for ($index = 0; $index -lt $limits.Count; $index++) {
            $record = $Archive.Position
            if ($record -gt $endRecord - $directoryHeaderSize -or $reader.ReadUInt32() -ne 0x02014b50) {
                throw 'Release ZIP has a malformed central directory record.'
            }
            $Archive.Position = $record + 8
            if ($reader.ReadUInt32() -ne 0) { throw 'Release ZIP only supports unflagged, stored files.' }
            $Archive.Position = $record + 16
            $crc = $reader.ReadUInt32()
            $stored = [long]$reader.ReadUInt32()
            $length = [long]$reader.ReadUInt32()
            $nameLength = $reader.ReadUInt16()
            if ($stored -ne $length -or $reader.ReadUInt32() -ne 0 -or
                $reader.ReadUInt16() -ne 0 -or $reader.ReadUInt16() -ne 0) {
                throw 'Release ZIP entry has an invalid size, extra field, comment, or disk number.'
            }
            $attributes = $reader.ReadUInt32()
            $unixType = ($attributes -shr 16) -band 0xf000
            if ($unixType -notin @(0, 0x8000) -or ($attributes -band 0x0450) -ne 0) {
                throw 'Release ZIP contains a link, reparse point, directory, or device.'
            }
            $localOffset = [long]$reader.ReadUInt32()
            if ($nameLength -gt $endRecord - $Archive.Position -or $localOffset -ne $nextLocal) {
                throw 'Release ZIP entry offsets do not describe a contiguous archive.'
            }
            $name = [Text.Encoding]::ASCII.GetString($reader.ReadBytes($nameLength))
            if (!$expected.Remove($name) -or $length -le 0 -or $length -gt $limits[$name]) {
                throw 'Release ZIP contains an unexpected name or out-of-bounds entry.'
            }

            $nextRecord = $Archive.Position
            $dataOffset = $localOffset + $localHeaderSize + $nameLength
            $nextLocal = $dataOffset + $length
            if ($nextLocal -gt $directoryOffset) { throw 'Release ZIP entry overlaps the central directory.' }
            $Archive.Position = $localOffset
            if ($reader.ReadUInt32() -ne 0x04034b50) { throw 'Release ZIP has an invalid local header.' }
            $Archive.Position = $localOffset + 6
            if ($reader.ReadUInt32() -ne 0) { throw 'Release ZIP local flags or compression method differ.' }
            $Archive.Position = $localOffset + 14
            if ($reader.ReadUInt32() -ne $crc -or $reader.ReadUInt32() -ne $length -or
                $reader.ReadUInt32() -ne $length -or $reader.ReadUInt16() -ne $nameLength -or
                $reader.ReadUInt16() -ne 0 -or
                [Text.Encoding]::ASCII.GetString($reader.ReadBytes($nameLength)) -cne $name) {
                throw 'Release ZIP local and central entry records differ.'
            }
            $members[$name] = [pscustomobject]@{ Offset = $dataOffset; Length = $length }
            $Archive.Position = $nextRecord
        }
        if ($nextLocal -ne $directoryOffset -or $Archive.Position -ne $endRecord -or $expected.Count -ne 0) {
            throw 'Release ZIP has hidden data or missing entries.'
        }
        return $members
    }
    finally { $reader.Dispose() }
}

function Expand-ExaCopyReleaseArchive {
    param(
        [IO.Stream] $Archive, [string] $ExpectedDigest, [string] $Stage,
        [Collections.Generic.List[string]] $Created
    )

    if (!$Archive.CanSeek -or $Archive.Length -le 0 -or $Archive.Length -gt $ExaCopyReleaseZipLimit) {
        throw 'Release ZIP is outside its byte limits.'
    }
    $Archive.Position = 0
    $digest = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Archive)).ToLowerInvariant()
    if ($digest -cne $ExpectedDigest) {
        throw 'Release ZIP SHA-256 differs from the pinned-tag checksum.'
    }
    $members = Read-ExaCopyReleaseArchiveEntries $Archive
    $buffer = [byte[]]::new(128KB)
    foreach ($name in $ExaCopyReleaseFiles) {
        $entry = $members[$name]
        $Archive.Position = $entry.Offset
        $remaining = $entry.Length
        $destination = [IO.FileStream]::new((Join-Path $Stage $name),
            [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $Created.Add($name)
        try {
            while ($remaining -gt 0) {
                $count = [int][Math]::Min($remaining, $buffer.Length)
                $Archive.ReadExactly($buffer, 0, $count)
                $destination.Write($buffer, 0, $count)
                $remaining -= $count
            }
            $destination.Flush($true)
        }
        finally { $destination.Dispose() }
    }
}
