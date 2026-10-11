import { createRoot } from 'react-dom/client'
import { App } from './App'
import { createClient } from './api'
import { createTokenStore } from './token'
import './styles.css'

const tokenStore = createTokenStore()
const client = createClient({ token: () => tokenStore.get() })
const container = document.getElementById('root')
if (!container) throw new Error('root element missing')

createRoot(container).render(<App client={client} tokenStore={tokenStore} />)
