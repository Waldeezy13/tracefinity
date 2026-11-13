# Exporting

## Bin export

From the bin editor, click **Export** to open the download menu. Available formats depend on what the bin contains.

### STL

Standard mesh format. Works with every slicer (PrusaSlicer, Cura, OrcaSlicer, etc.).

If the bin is too large for the configured bed size or the bin is separated by the partial bins configuration, the export menu shows **Full STL** (the merged file) and **ZIP** (split parts as separate STLs). The split count is shown in the sidebar banner.

### 3MF

Compressed format with multi-body support. Only generated when the bin has text labels, because the label geometry is stored as a separate body for multi-colour printing. The bin body and text body are exported as distinct objects in the 3MF file.

Internally uses trimesh for the 3MF scene assembly. The bin and text manifolds are converted to trimesh meshes and exported as named geometries.

### Insert STL

Available when **Contrast Insert** is enabled in the bin configuration. This is a separate STL of just the insert piece, intended for printing in a contrasting colour. Download it from the export menu alongside the main bin STL.

## Automatic remote export

Set `RCLONE_EXPORT_REMOTE` to a configured rclone remote and optional prefix,
for example `drive:Tracefinity`. It is disabled when unset or empty. Install
`rclone` when running the backend outside Docker; both supplied images include
it. Configure credentials with rclone's normal configuration or `RCLONE_CONFIG_*`
environment variables. For Docker, mount an rclone config file and set
`RCLONE_CONFIG` to its container path; the runtime user must be able to read it
and write it if the provider needs rclone to refresh tokens. Protect the config
and credentials as secrets. The Helm chart supports `envFrom`
and secret volumes for this purpose.

Each successful saved-bin generation, including a cached generation, copies the
full STL and any generated 3MF, parts ZIP and insert STL into a directory named
for the bin under the prefix. Unsafe name characters are replaced and names
are bounded. Filenames include the bin name and a 16-hex-digit hash of the user
and bin IDs to avoid collisions between bins or users with the same name.
Session generation is not exported.

Only these generated filenames are overwritten; no other remote files are
deleted. Files for formats no longer generated, renamed bins, and deleted bins
remain remotely until removed manually. Local retention does not remove remote
exports. A failed transfer may leave a partial remote update. Failures return
HTTP 502 while retaining locally generated files; retry generation to retry the
export (including when geometry is cached). Server logs include the failure
category or rclone exit status, not rclone's potentially sensitive output. The
export runs under the bin generation lock with a 90-second overall timeout.

## Tool export

From the tool editor, download the outline as an SVG file. Useful for laser cutting, CNC routing, or importing into CAD software.

## Print recommendations

Tracefinity bins are standard Gridfinity geometry, so the usual print settings apply:

| Setting | Recommendation |
|-|-|
| Layer height | 0.2mm default. 0.16mm for a smoother stacking lip. |
| Infill | 10-15%. Bin walls are thin and do not need much internal structure. |
| Supports | Not needed. Bins are designed to print without supports. |
| Material | PLA works well. PETG for more durability. |
| Orientation | Print with the base down (the default orientation in the exported file). |
