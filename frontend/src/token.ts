export interface TokenStore {
  get(): string
  set(token: string): void
  clear(): void
  subscribe(listener: () => void): () => void
}

/**
 * Operator token held only in an in-memory closure variable.
 *
 * It is deliberately never written to localStorage, sessionStorage, cookies,
 * the URL, logs, or any build artifact. A page reload therefore forgets it and
 * the operator re-enters it.
 */
export function createTokenStore(): TokenStore {
  let token = ''
  const listeners = new Set<() => void>()

  function notify() {
    for (const listener of listeners) listener()
  }

  return {
    get: () => token,
    set: (next: string) => {
      token = next
      notify()
    },
    clear: () => {
      token = ''
      notify()
    },
    subscribe: (listener: () => void) => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
  }
}
