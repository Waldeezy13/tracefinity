// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { BinEditorToolbar } from './BinEditorToolbar'

afterEach(cleanup)

const selectedTool = {
  id: 'placed', tool_id: 'square', name: 'Square', points: [],
  finger_holes: [], interior_rings: [], rotation: 0, depth_override: 14,
}
const props = {
  activeTool: 'select' as const, setActiveTool: vi.fn(), snapEnabled: false,
  setSnapEnabled: vi.fn(), snapGrid: 1, setSnapGrid: vi.fn(), handleRecenter: vi.fn(),
  selectedTool, selectedLabel: null, selectedHole: null, selectedHoleToolId: null,
  onRemoveTool: vi.fn(), onRemoveLabel: vi.fn(), onUpdateLabel: vi.fn(),
  defaultCutoutDepth: 20, maxCutoutDepth: 14.25,
  onSetCutoutDepthOverride: vi.fn(), onSetHoleDepthOverride: vi.fn(),
}

describe('per-feature depth controls', () => {
  it('updates an existing override when the bin gets shallower', () => {
    const onSetCutoutDepthOverride = vi.fn()
    const { rerender } = render(<BinEditorToolbar {...props} onSetCutoutDepthOverride={onSetCutoutDepthOverride} />)
    const depth = screen.getByPlaceholderText('14.25')
    expect(depth.getAttribute('value')).toBe('14')
    rerender(<BinEditorToolbar {...props} maxCutoutDepth={0.25} onSetCutoutDepthOverride={onSetCutoutDepthOverride} />)
    expect(depth.getAttribute('value')).toBe('0.25')
    fireEvent.change(depth, { target: { value: '7' } })
    fireEvent.blur(depth)
    expect(onSetCutoutDepthOverride).toHaveBeenCalledWith('placed', 0.25)
  })

  it('allows a finger hole to reach the same maximum as its tool', () => {
    const onSetHoleDepthOverride = vi.fn()
    render(<BinEditorToolbar {...props} selectedTool={null} selectedHoleToolId="placed"
      selectedHole={{ id: 'hole', x: 1, y: 1, radius: 2, shape: 'cylinder' }}
      maxCutoutDepth={7.25} onSetHoleDepthOverride={onSetHoleDepthOverride} />)
    const depth = screen.getByPlaceholderText('7.25')
    fireEvent.change(depth, { target: { value: '8' } })
    fireEvent.blur(depth)
    expect(onSetHoleDepthOverride).toHaveBeenCalledWith('placed', 'hole', 7.25)
  })

  it('shows the parent tool depth as the inherited hole depth', () => {
    render(<BinEditorToolbar {...props} selectedTool={null} selectedHoleToolId="placed"
      selectedHole={{ id: 'hole', x: 1, y: 1, radius: 2, shape: 'cylinder' }}
      selectedHoleDefaultDepth={8} />)
    expect(screen.getByPlaceholderText('8.00')).toBeTruthy()
  })
})
