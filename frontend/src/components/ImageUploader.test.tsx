// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { ImageUploader } from './ImageUploader'

vi.mock('@/hooks/useReducedMotion', () => ({ useReducedMotion: () => true }))

describe('ImageUploader', () => {
  afterEach(cleanup)

  it('opens the rear camera and uploads the captured image', () => {
    const onUpload = vi.fn()
    const { container } = render(<ImageUploader onUpload={onUpload} />)
    const camera = container.querySelector('input[capture="environment"]') as HTMLInputElement
    const click = vi.spyOn(camera, 'click')

    fireEvent.click(screen.getByRole('button', { name: 'Take photo' }))
    expect(click).toHaveBeenCalledOnce()
    expect(camera.accept).toBe('image/*')
    expect(screen.getByText(/50–60 cm or more/)).toBeTruthy()

    const photo = new File(['photo'], 'photo.jpg', { type: 'image/jpeg' })
    fireEvent.change(camera, { target: { files: [photo] } })
    expect(onUpload).toHaveBeenCalledWith(photo)
  })

  it('supports choosing a photo and prevents either action while uploading', () => {
    const onUpload = vi.fn()
    const { container, rerender } = render(<ImageUploader onUpload={onUpload} />)
    const chooser = container.querySelector('input:not([capture])') as HTMLInputElement
    const click = vi.spyOn(chooser, 'click')
    fireEvent.click(screen.getByRole('button', { name: 'Upload photo' }))
    expect(click).toHaveBeenCalledOnce()
    const photo = new File(['photo'], 'photo.jpg', { type: 'image/jpeg' })
    fireEvent.change(chooser, { target: { files: [photo] } })
    expect(onUpload).toHaveBeenCalledWith(photo)

    rerender(<ImageUploader onUpload={onUpload} disabled />)
    expect((screen.getByRole('button', { name: 'Upload photo' }) as HTMLButtonElement).disabled).toBe(true)
    expect((screen.getByRole('button', { name: 'Take photo' }) as HTMLButtonElement).disabled).toBe(true)
  })
})
