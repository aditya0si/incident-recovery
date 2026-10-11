import { describe, expect, it, beforeEach, vi } from 'vitest'
import { createTokenStore } from './token'

describe('in-memory operator token store', () => {
  beforeEach(() => {
    window.localStorage.clear()
    window.sessionStorage.clear()
  })

  it('holds a token only in memory', () => {
    const store = createTokenStore()
    store.set('super-secret-operator-token')
    expect(store.get()).toBe('super-secret-operator-token')
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(0)
    expect(JSON.stringify(window.localStorage)).not.toContain('super-secret-operator-token')
    expect(JSON.stringify(window.sessionStorage)).not.toContain('super-secret-operator-token')
  })

  it('clears the token and notifies without persisting', () => {
    const store = createTokenStore()
    const listener = vi.fn()
    const unsubscribe = store.subscribe(listener)
    store.set('abc')
    expect(listener).toHaveBeenCalledTimes(1)
    store.clear()
    expect(store.get()).toBe('')
    expect(listener).toHaveBeenCalledTimes(2)
    unsubscribe()
    store.set('def')
    expect(listener).toHaveBeenCalledTimes(2)
    expect(window.localStorage.length).toBe(0)
  })

  it('never writes to storage keys', () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem')
    const store = createTokenStore()
    store.set('xyz')
    store.clear()
    expect(setItem).not.toHaveBeenCalled()
    setItem.mockRestore()
  })
})
