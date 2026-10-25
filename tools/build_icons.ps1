$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Drawing

$repo = Split-Path $PSScriptRoot -Parent
$root = Join-Path $repo "shellsuite\gui\assets"
$source = Join-Path $root "source"

if (-not (Test-Path -LiteralPath $source)) {
    throw "Missing source icon directory: $source"
}

$colors = @{
    "text" = "#D4D4D4"
    "muted" = "#9D9D9D"
    "accent" = "#D20A0A"
    "accent-hover" = "#E8261F"
}

$variants = @(
    @{ Kind = "logo"; Size = 90; Role = "text"; Fit = $true },
    @{ Kind = "chevron"; Size = 14; Role = "muted"; Fit = $false },
    @{ Kind = "globe"; Size = 60; Role = "muted"; Fit = $false },
    @{ Kind = "globe"; Size = 60; Role = "text"; Fit = $false },
    @{ Kind = "clock"; Size = 60; Role = "muted"; Fit = $false },
    @{ Kind = "clock"; Size = 60; Role = "text"; Fit = $false },
    @{ Kind = "terminal"; Size = 35; Role = "text"; Fit = $false },
    @{ Kind = "edit"; Size = 35; Role = "text"; Fit = $false },
    @{ Kind = "trash"; Size = 35; Role = "accent"; Fit = $false },
    @{ Kind = "trash"; Size = 35; Role = "accent-hover"; Fit = $false },
    @{ Kind = "plus"; Size = 26; Role = "text"; Fit = $false },
    @{ Kind = "close"; Size = 18; Role = "accent"; Fit = $false },
    @{ Kind = "close"; Size = 18; Role = "accent-hover"; Fit = $false },
    @{ Kind = "close"; Size = 12; Role = "muted"; Fit = $false }
)

function New-TintedIcon {
    param($Kind, [int]$Size, $Role, [bool]$Fit)

    $sourcePath = Join-Path $source "$Kind.png"
    if (-not (Test-Path -LiteralPath $sourcePath)) {
        throw "Missing source icon: $sourcePath"
    }
    if (-not $colors.ContainsKey($Role)) {
        throw "Unknown icon colour role: $Role"
    }

    $sourceImage = [System.Drawing.Image]::FromFile($sourcePath)
    $bitmap = New-Object System.Drawing.Bitmap($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.Clear([System.Drawing.Color]::Transparent)
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $graphics.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceOver

    if ($Fit) {
        $scale = [Math]::Min($Size / $sourceImage.Width, $Size / $sourceImage.Height)
        $drawWidth = [int][Math]::Round($sourceImage.Width * $scale)
        $drawHeight = [int][Math]::Round($sourceImage.Height * $scale)
        $drawX = [int](($Size - $drawWidth) / 2)
        $drawY = [int](($Size - $drawHeight) / 2)
    } else {
        $drawWidth = $Size
        $drawHeight = $Size
        $drawX = 0
        $drawY = 0
    }

    $rect = New-Object System.Drawing.Rectangle($drawX, $drawY, $drawWidth, $drawHeight)
    $graphics.DrawImage($sourceImage, $rect)
    $graphics.Dispose()
    $sourceImage.Dispose()

    $color = [System.Drawing.ColorTranslator]::FromHtml($colors[$Role])
    for ($y = 0; $y -lt $Size; $y++) {
        for ($x = 0; $x -lt $Size; $x++) {
            $pixel = $bitmap.GetPixel($x, $y)
            if ($pixel.A -gt 0) {
                $bitmap.SetPixel($x, $y, [System.Drawing.Color]::FromArgb($pixel.A, $color.R, $color.G, $color.B))
            }
        }
    }

    $outputPath = Join-Path $root ("{0}-{1}-{2}.png" -f $Kind, $Size, $Role)
    $bitmap.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bitmap.Dispose()
    Write-Output ("{0} -> {1}x{2}" -f (Split-Path $outputPath -Leaf), $Size, $Size)
}

foreach ($variant in $variants) {
    New-TintedIcon -Kind $variant.Kind -Size $variant.Size -Role $variant.Role -Fit $variant.Fit
}

function New-AppIcon {
    param([int]$Size)

    $sourcePath = Join-Path $source "logo.png"
    if (-not (Test-Path -LiteralPath $sourcePath)) {
        throw "Missing source icon: $sourcePath"
    }

    $sourceImage = [System.Drawing.Image]::FromFile($sourcePath)
    $mark = New-Object System.Drawing.Bitmap($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $markGraphics = [System.Drawing.Graphics]::FromImage($mark)
    $markGraphics.Clear([System.Drawing.Color]::Transparent)
    $markGraphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $markGraphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $markGraphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $markGraphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality

    $sourceSide = [Math]::Min($sourceImage.Width, $sourceImage.Height)
    $sourceRect = New-Object System.Drawing.Rectangle(0, 0, $sourceSide, $sourceSide)
    $content = [int][Math]::Round($Size * 0.78)
    $offset = [int](($Size - $content) / 2)
    $destRect = New-Object System.Drawing.Rectangle($offset, $offset, $content, $content)
    $markGraphics.DrawImage($sourceImage, $destRect, $sourceRect, [System.Drawing.GraphicsUnit]::Pixel)
    $markGraphics.Dispose()
    $sourceImage.Dispose()

    $markColor = [System.Drawing.ColorTranslator]::FromHtml("#D4D4D4")
    for ($y = 0; $y -lt $Size; $y++) {
        for ($x = 0; $x -lt $Size; $x++) {
            $pixel = $mark.GetPixel($x, $y)
            if ($pixel.A -gt 0) {
                $mark.SetPixel($x, $y, [System.Drawing.Color]::FromArgb($pixel.A, $markColor.R, $markColor.G, $markColor.B))
            }
        }
    }

    $tile = New-Object System.Drawing.Bitmap($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $tileGraphics = [System.Drawing.Graphics]::FromImage($tile)
    $tileGraphics.Clear([System.Drawing.Color]::Transparent)
    $tileGraphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

    $radius = [Math]::Max(2, [int][Math]::Round($Size * 0.18))
    $diameter = $radius * 2
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc(0, 0, $diameter, $diameter, 180, 90)
    $path.AddArc($Size - $diameter, 0, $diameter, $diameter, 270, 90)
    $path.AddArc($Size - $diameter, $Size - $diameter, $diameter, $diameter, 0, 90)
    $path.AddArc(0, $Size - $diameter, $diameter, $diameter, 90, 90)
    $path.CloseFigure()
    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.ColorTranslator]::FromHtml("#1E1E1E"))
    $tileGraphics.FillPath($brush, $path)
    $tileGraphics.DrawImage($mark, 0, 0, $Size, $Size)

    $tileGraphics.Dispose()
    $brush.Dispose()
    $path.Dispose()
    $mark.Dispose()

    $outputPath = Join-Path $root ("appicon-{0}.png" -f $Size)
    $tile.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $tile.Dispose()
    Write-Output ("{0} -> {1}x{1}" -f (Split-Path $outputPath -Leaf), $Size)
}

foreach ($size in @(16, 32, 48, 64, 256)) {
    New-AppIcon -Size $size
}
