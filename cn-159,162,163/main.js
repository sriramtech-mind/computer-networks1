import './style.css'
import { createClient } from '@supabase/supabase-js'
import { ThreatDetector } from './threatDetector.js'
import { NetworkMonitor } from './networkMonitor.js'
import { UIManager } from './uiManager.js'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY

const supabase = createClient(supabaseUrl, supabaseAnonKey)

const threatDetector = new ThreatDetector(supabase)
const networkMonitor = new NetworkMonitor(supabase, threatDetector)
const uiManager = new UIManager(supabase, networkMonitor)

window.uiManager = uiManager

uiManager.init()
networkMonitor.start()
