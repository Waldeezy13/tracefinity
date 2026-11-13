# Uploading Photos

## Paper as a size reference

Tracefinity uses a sheet of paper as a known-size reference to scale outlines to real-world dimensions. Place tools flat on A4, Letter, A3, or Tabloid paper.

The paper is for scale only. Tools can overflow the paper edges. The full visible area beyond the paper is included in the corrected image.
## Marker mat as a size reference

You can instead use a flat cutting mat with four printed ArUco markers. Use the
OpenCV **DICT_4X4_50** dictionary, IDs **0, 1, 2, 3**, with their centres at
the corners of a rectangle, in this order:

```text
0 ---------------- 1
|                  |
|   tools here     |
|                  |
3 ---------------- 2
```

Keep the markers coplanar with the tools' resting surface, flat, unobstructed,
and separated from the tools. Include all four in the photo, including a white
margin around each marker. The spacing need not be a particular size: measure
the horizontal centre-to-centre distance from 0 to 1 and the vertical distance
from 0 to 3 in millimetres. Opposite sides must have the same spacing and the
corners must be square. For example, a 200 × 200 mm centre rectangle with
15 mm markers leaves a useful working area; measure the actual arrangement
rather than relying on the nominal dimensions.

To generate printable marker images, with the backend dependencies installed:

```bash
cd backend
python -c 'import cv2; d=cv2.aruco.getPredefinedDictionary(cv2.aruco.DICT_4X4_50); [cv2.imwrite(f"marker-{i}.png", cv2.aruco.generateImageMarker(d, i, 600)) for i in range(4)]'
```

Print the four images as squares with a white border, at a size large enough to
be clearly resolved in the photo (15 mm is a useful starting point). Disable
fit-to-page and verify their size with a ruler. Attach them to the mat in the
arrangement above, then measure the actual centre spacings after attachment.
Keep tools inside the marker rectangle, clear of the markers. For local saliency
tracers, the initial crop is inset 4% from each marker centre; use markers no
wider than 8% of either centre spacing and keep tools clear of that inset.

After uploading, the marker centres are detected automatically when all four
are visible. Confirm or drag the handles to their centres, and enter both
measured spacings before continuing. These values determine the physical scale;
the grid printed on a mat is not assumed to have any particular spacing. If
markers cannot be detected, use the paper reference instead. If a paper
reference is also visible, the reference selector lets you switch to it and
adjust its corners. Photo stations currently save paper calibration only.


## Capture on a phone

Open the dashboard on your phone and select **Take photo** to open the rear camera.
Frame the reference and tools from directly above, at least 50–60 cm away.
Keep all four paper corners or markers visible, with the reference taking up
around half the frame.
After taking the picture, accept it in the camera app to upload it. Alternatively,
choose **Upload photo** to select an existing image. The upload opens the normal
calibration, tracing, and save-tools workflow.

After saving tools, create a bin from the dashboard. On a narrow screen the bin
settings, tool library, layout editor, and 3D preview are stacked vertically;
tap a library tool to add it, set the desired cutout depth in the settings or
select a tool in the layout to override its depth, then use **Export** when
generation finishes to download the STL.

## Tips for good results

- **Contrasting background** -- use a dark surface under white paper (or vice versa). The AI needs to distinguish paper edges from the background.
- **Even lighting** -- avoid harsh shadows across the tools. Diffused overhead light works best.
- **Flat tools** -- tools should lie flat on the paper. Raised handles or 3D shapes confuse the mask generation.
- **No overlap** -- leave a small gap between tools so the AI can separate them.
- **Shoot from above** -- aim for directly overhead. Perspective correction handles some angle, but straight-down needs the least correction. Overhead does not mean close up: distance matters more than angle for scale accuracy.
- **Shoot from a distance** -- 50-60cm or more, with the page filling around half the frame. The paper calibrates the table surface, so anything raised above it projects oversized by H/(H-t) (camera height H, tool thickness t). A thick tool shot from around 20cm can trace roughly 8% too large; from 60cm or more that drops to around 2%.

## Photo warnings

After you confirm the paper corners, Tracefinity checks the photo and flags problems that reduce trace accuracy:

- **Camera too close** -- estimated from the photo's EXIF data. Close shots exaggerate outlines of thick tools (a 15 mm-thick tool shot from 25 cm traces roughly 6% oversized). Shoot from 60 cm or higher. Skipped when the photo has no EXIF data (e.g. screenshots), or when its EXIF records a different pixel size than the file has, as after a crop or resize. An editor that rewrites the EXIF size hides the crop, and the estimate then reads too close.
- **Paper cut off** -- a paper corner sits at or beyond the photo edge.
- **Extreme perspective** -- a strong camera angle degrades edge accuracy even after correction.

Warnings are advisory: you can dismiss them and continue, but retaking the photo gives better results.

## Supported formats

JPG, PNG, WebP, and HEIC. Uploads are limited to 20 MB and 64 megapixels by
default. Self-hosted instances can tune these limits with `MAX_UPLOAD_MB` and
`MAX_IMAGE_PIXELS`.

Images are automatically downscaled to a maximum of 2048px on the longest edge. Original uploads are deleted after perspective correction; only the corrected image is retained.

## Paper size

After uploading, select A4, Letter, A3, or Tabloid. Pick whichever you actually used. This determines the scale of everything downstream: tool outlines, bin dimensions, and exported STL geometry.

## Troubleshooting

- **Cutout comes out a few percent larger than the tool** -- the photo was taken too close. The paper sits on the table, but a thick tool's outline sits above it, nearer the camera, so it projects oversized. Re-shoot from 50-60cm or more.
