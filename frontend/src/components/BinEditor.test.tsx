// @vitest-environment jsdom
import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { BinEditor } from './BinEditor'
import { SNAP_GRID } from '@/lib/constants'

const baseProps = {
  placedTools: [],
  onPlacedToolsChange: () => {},
  textLabels: [],
  onTextLabelsChange: () => {},
  gridX: 2,
  gridY: 2,
  partialBins: false,
  partialBinsValues: [false, false],
  wallThickness: 1.6,
  defaultCutoutDepth: 10,
  maxCutoutDepth: 20,
}

describe('BinEditor snap to grid', () => {
  afterEach(cleanup)

  it('defaults to off', () => {
    render(<BinEditor {...baseProps} />)

    expect(screen.getByTitle(`Snap to ${SNAP_GRID}mm grid (off)`)).toBeTruthy()
  })

  it('can be toggled on', () => {
    render(<BinEditor {...baseProps} />)

    fireEvent.click(screen.getByTitle(`Snap to ${SNAP_GRID}mm grid (off)`))

    expect(screen.getByTitle(`Snap to ${SNAP_GRID}mm grid (on)`)).toBeTruthy()
  })
})

describe('BinEditor touch selection', () => {
  afterEach(cleanup)

  it('selects a tool on touch so its depth can be edited', () => {
    const tool = {
      id: 'placed', tool_id: 'square', name: 'Square',
      points: [{ x: 0, y: 0 }, { x: 10, y: 0 }, { x: 10, y: 10 }],
      finger_holes: [], interior_rings: [], rotation: 0, depth_override: null,
    }
    const { container } = render(<BinEditor {...baseProps} placedTools={[tool]} />)
    const path = container.querySelector('path[fill-rule="evenodd"]')!
    fireEvent.touchStart(path, { touches: [{ clientX: 20, clientY: 20 }] })
    expect(screen.getByPlaceholderText('10.00')).toBeTruthy()
    fireEvent.touchEnd(window)
  })
})
