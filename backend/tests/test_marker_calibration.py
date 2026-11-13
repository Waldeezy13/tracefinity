import asyncio

import cv2
import numpy as np
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import app.api.routes as routes
from app.config import ensure_user_dirs
from app.main import app
from app.models.schemas import CornersRequest
from app.services.ai_tracer import AITracer
from app.services.image_processor import ImageProcessor, detect_marker_corners


def marker_photo(path):
    image = np.full((600, 800), 255, dtype=np.uint8)
    dictionary = cv2.aruco.getPredefinedDictionary(cv2.aruco.DICT_4X4_50)
    for marker_id, (x, y) in enumerate([(100, 100), (600, 100), (600, 400), (100, 400)]):
        image[y:y + 60, x:x + 60] = cv2.aruco.generateImageMarker(dictionary, marker_id, 60)
    cv2.rectangle(image, (240, 220), (440, 320), 0, -1)
    cv2.imwrite(str(path), image)


def test_detects_marker_centres_and_rejects_missing_marker(tmp_path):
    path = tmp_path / 'markers.png'
    marker_photo(path)
    centers = detect_marker_corners(str(path))
    assert centers is not None
    assert np.allclose(centers, [(129.5, 129.5), (629.5, 129.5), (629.5, 429.5), (129.5, 429.5)], atol=1)
    image = cv2.imread(str(path))
    image[400:460, 100:160] = 255
    cv2.imwrite(str(path), image)
    assert detect_marker_corners(str(path)) is None


def test_marker_dimensions_drive_warp_scale_without_orientation_guess(tmp_path):
    uploads = tmp_path / 'uploads'
    uploads.mkdir()
    (tmp_path / 'processed').mkdir()
    path = uploads / 'markers.png'
    marker_photo(path)
    corners = detect_marker_corners(str(path))
    bounds = []
    output, scale = ImageProcessor().apply_perspective_correction(
        str(path), corners, 'a4', 2048, marker_dimensions=(200.13, 90.27), marker_bounds=bounds
    )
    assert scale > 0
    assert len(bounds) == 4 and bounds[2] > 0 and bounds[3] > 0
    # The dark rectangle spans known fractions of the marker spacings.
    corrected = cv2.imread(output, cv2.IMREAD_GRAYSCALE)
    count, _, stats, _ = cv2.connectedComponentsWithStats((corrected < 80).astype(np.uint8))
    components = sorted(stats[1:count], key=lambda component: component[4], reverse=True)
    assert components[0][2] * scale == pytest.approx(200 / 500 * 200.13, abs=1)
    assert components[0][3] * scale == pytest.approx(100 / 300 * 90.27, abs=1)


def test_marker_crop_bypasses_bright_paper_detection(tmp_path, monkeypatch):
    path = tmp_path / 'mat.png'
    image = np.full((400, 500, 3), (40, 100, 40), np.uint8)
    cv2.rectangle(image, (200, 160), (260, 240), (10, 10, 10), -1)
    cv2.imwrite(str(path), image)
    tracer = AITracer(saliency_tracer='fal', remote_model='m', remote_token='x')
    crops = []

    async def saliency(image):
        crops.append(image.size)
        return np.where(np.asarray(image.convert('L')) < 20, 255, 0).astype(np.uint8)

    def no_paper(_image):
        raise AssertionError('paper detection must not run for marker mats')

    monkeypatch.setattr(tracer, '_saliency_on_image', saliency)
    monkeypatch.setattr(tracer, '_detect_paper_rect', no_paper)
    output = asyncio.run(tracer._generate_mask_saliency(
        str(path), str(tmp_path / 'mask.png'), saliency_crop=(100, 100, 300, 200)
    ))
    mask = cv2.imread(output, cv2.IMREAD_GRAYSCALE)
    assert crops == [(300, 200)]
    assert mask[200, 230] == 0
    assert mask[20, 20] == 255


def test_upload_and_confirm_measured_marker_scale(tmp_path, monkeypatch):
    monkeypatch.setattr(routes.settings, 'storage_path', tmp_path)
    routes._store_cache.clear()
    ensure_user_dirs(tmp_path / 'default')
    monkeypatch.setattr(routes.image_processor, 'detect_paper_corners', lambda _: None)
    path = tmp_path / 'input.png'
    marker_photo(path)
    client = TestClient(app)
    response = client.post('/api/upload', files={'image': ('photo.png', path.read_bytes(), 'image/png')})
    assert response.status_code == 200
    session_id = response.json()['session_id']
    session = client.get(f'/api/sessions/{session_id}').json()
    assert len(session['marker_corners']) == 4
    assert session['paper_corners'] is None
    response = client.post(f'/api/sessions/{session_id}/corners', json={
        'corners': session['marker_corners'],
        'paper_size': 'a4',
        'marker_width_mm': 200.13,
        'marker_height_mm': 90.27,
    })
    assert response.status_code == 200
    session = client.get(f'/api/sessions/{session_id}').json()
    assert session['marker_width_mm'] == 200.13
    assert session['marker_height_mm'] == 90.27
    assert len(session['marker_bounds']) == 4


def test_marker_dimensions_must_be_a_finite_positive_pair():
    corners = [{'x': 0, 'y': 0}] * 4
    for values in ({'marker_width_mm': 200}, {'marker_width_mm': 0, 'marker_height_mm': 100},
                   {'marker_width_mm': float('nan'), 'marker_height_mm': 100}):
        with pytest.raises(ValidationError):
            CornersRequest(corners=corners, paper_size='a4', **values)
    assert CornersRequest(corners=corners, paper_size='a4').marker_width_mm is None
