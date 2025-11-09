export class UIManager {
  constructor(supabase, networkMonitor) {
    this.supabase = supabase
    this.networkMonitor = networkMonitor
    this.chartData = []
    this.maxChartPoints = 20
  }

  init() {
    this.setupEventListeners()
    this.startDataRefresh()
    this.initializeChart()
  }

  setupEventListeners() {
    document.getElementById('blockIpBtn').addEventListener('click', () => {
      this.showModal('blockIpModal')
    })

    document.getElementById('closeModal').addEventListener('click', () => {
      this.hideModal('blockIpModal')
    })

    document.getElementById('closeEventModal').addEventListener('click', () => {
      this.hideModal('eventModal')
    })

    document.getElementById('addBlockBtn').addEventListener('click', () => {
      this.blockIP()
    })

    document.getElementById('refreshBtn').addEventListener('click', () => {
      this.refreshData()
    })

    document.getElementById('alertFilter').addEventListener('change', (e) => {
      this.filterAlerts(e.target.value)
    })

    document.getElementById('searchEvents').addEventListener('input', (e) => {
      this.searchEvents(e.target.value)
    })

    document.querySelectorAll('.modal').forEach(modal => {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          this.hideModal(modal.id)
        }
      })
    })
  }

  startDataRefresh() {
    this.refreshData()
    setInterval(() => {
      this.refreshData()
    }, 5000)
  }

  async refreshData() {
    await Promise.all([
      this.updateStats(),
      this.updateAlerts(),
      this.updateEvents(),
      this.updateChart()
    ])
  }

  async updateStats() {
    const stats = this.networkMonitor.getStats()

    document.getElementById('totalTraffic').textContent =
      (stats.totalTraffic / (1024 * 1024 * 1024)).toFixed(2) + ' GB'

    document.getElementById('activeConnections').textContent =
      stats.activeConnections.toLocaleString()

    document.getElementById('threatsDetected').textContent =
      stats.threatsDetected.toLocaleString()

    document.getElementById('threatsBlocked').textContent =
      stats.threatsBlocked.toLocaleString()
  }

  async updateAlerts() {
    const alerts = await this.networkMonitor.getRecentAlerts()
    const container = document.getElementById('alertsList')

    if (alerts.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          </svg>
          <p>No alerts detected</p>
        </div>
      `
      return
    }

    container.innerHTML = alerts.map(alert => `
      <div class="alert-item ${alert.severity}" onclick="window.uiManager.acknowledgeAlert('${alert.id}')">
        <div class="alert-header">
          <span class="alert-title">${alert.title}</span>
          <span class="alert-badge ${alert.severity}">${alert.severity}</span>
        </div>
        <p class="alert-message">${alert.message}</p>
        <span class="alert-time">${this.formatTime(alert.created_at)}</span>
      </div>
    `).join('')
  }

  async updateEvents() {
    const events = await this.networkMonitor.getRecentEvents(50)
    const tbody = document.getElementById('eventsTable')

    if (events.length === 0) {
      tbody.innerHTML = '<tr><td colspan="8" class="no-data">No events recorded</td></tr>'
      return
    }

    tbody.innerHTML = events.map(event => `
      <tr onclick="window.uiManager.showEventDetails('${event.id}')">
        <td>${this.formatTime(event.timestamp)}</td>
        <td>${event.source_ip}</td>
        <td>${event.destination_ip}</td>
        <td>${event.protocol}</td>
        <td>${event.port}</td>
        <td><span class="threat-badge ${event.threat_level}">${event.threat_level}</span></td>
        <td><span class="status-badge ${event.is_blocked ? 'blocked' : 'allowed'}">
          ${event.is_blocked ? 'Blocked' : 'Allowed'}
        </span></td>
        <td>
          ${!event.is_blocked && event.threat_level !== 'low' ?
            `<button class="btn btn-danger" onclick="event.stopPropagation(); window.uiManager.blockIPFromEvent('${event.source_ip}')">Block</button>` :
            '-'
          }
        </td>
      </tr>
    `).join('')
  }

  initializeChart() {
    const canvas = document.getElementById('chartCanvas')
    this.ctx = canvas.getContext('2d')
    this.drawChart()
  }

  async updateChart() {
    const stats = this.networkMonitor.getStats()

    this.chartData.push({
      time: new Date().toLocaleTimeString(),
      threats: stats.threatsDetected
    })

    if (this.chartData.length > this.maxChartPoints) {
      this.chartData.shift()
    }

    this.drawChart()
  }

  drawChart() {
    if (!this.ctx) return

    const canvas = this.ctx.canvas
    const width = canvas.width
    const height = canvas.height

    this.ctx.clearRect(0, 0, width, height)

    if (this.chartData.length < 2) return

    const maxValue = Math.max(...this.chartData.map(d => d.threats), 10)
    const padding = 40
    const chartWidth = width - padding * 2
    const chartHeight = height - padding * 2

    this.ctx.strokeStyle = '#2d3748'
    this.ctx.lineWidth = 1

    for (let i = 0; i <= 5; i++) {
      const y = padding + (chartHeight / 5) * i
      this.ctx.beginPath()
      this.ctx.moveTo(padding, y)
      this.ctx.lineTo(width - padding, y)
      this.ctx.stroke()

      this.ctx.fillStyle = '#9ca3af'
      this.ctx.font = '12px sans-serif'
      this.ctx.fillText(Math.round(maxValue * (5 - i) / 5), 5, y + 4)
    }

    this.ctx.strokeStyle = '#3b82f6'
    this.ctx.lineWidth = 3
    this.ctx.beginPath()

    this.chartData.forEach((point, i) => {
      const x = padding + (chartWidth / (this.chartData.length - 1)) * i
      const y = padding + chartHeight - (point.threats / maxValue) * chartHeight

      if (i === 0) {
        this.ctx.moveTo(x, y)
      } else {
        this.ctx.lineTo(x, y)
      }
    })

    this.ctx.stroke()

    this.ctx.fillStyle = '#3b82f6'
    this.chartData.forEach((point, i) => {
      const x = padding + (chartWidth / (this.chartData.length - 1)) * i
      const y = padding + chartHeight - (point.threats / maxValue) * chartHeight

      this.ctx.beginPath()
      this.ctx.arc(x, y, 4, 0, Math.PI * 2)
      this.ctx.fill()
    })
  }

  async blockIP() {
    const ipInput = document.getElementById('ipToBlock')
    const reasonInput = document.getElementById('blockReason')

    const ip = ipInput.value.trim()
    const reason = reasonInput.value.trim()

    if (!ip || !reason) {
      alert('Please enter both IP address and reason')
      return
    }

    const { error } = await this.supabase
      .from('blocked_ips')
      .insert([{
        ip_address: ip,
        reason: reason,
        is_active: true
      }])

    if (error) {
      alert('Error blocking IP: ' + error.message)
      return
    }

    ipInput.value = ''
    reasonInput.value = ''

    await this.loadBlockedIPs()
  }

  async blockIPFromEvent(ip) {
    const reason = prompt(`Enter reason for blocking ${ip}:`)
    if (!reason) return

    const { error } = await this.supabase
      .from('blocked_ips')
      .insert([{
        ip_address: ip,
        reason: reason,
        is_active: true
      }])

    if (error) {
      alert('Error blocking IP: ' + error.message)
      return
    }

    alert(`IP ${ip} has been blocked`)
    this.refreshData()
  }

  async loadBlockedIPs() {
    const { data: blockedIPs } = await this.supabase
      .from('blocked_ips')
      .select('*')
      .eq('is_active', true)
      .order('blocked_at', { ascending: false })

    const container = document.getElementById('blockedIpsList')

    if (!blockedIPs || blockedIPs.length === 0) {
      container.innerHTML = '<div class="empty-state"><p>No IPs blocked</p></div>'
      return
    }

    container.innerHTML = blockedIPs.map(ip => `
      <div class="blocked-ip-item">
        <div class="blocked-ip-info">
          <div class="blocked-ip-address">${ip.ip_address}</div>
          <div class="blocked-ip-reason">${ip.reason}</div>
        </div>
        <button class="btn btn-secondary" onclick="window.uiManager.unblockIP('${ip.id}')">Unblock</button>
      </div>
    `).join('')
  }

  async unblockIP(id) {
    const { error } = await this.supabase
      .from('blocked_ips')
      .update({ is_active: false })
      .eq('id', id)

    if (error) {
      alert('Error unblocking IP: ' + error.message)
      return
    }

    await this.loadBlockedIPs()
  }

  async showEventDetails(eventId) {
    const { data: event } = await this.supabase
      .from('network_events')
      .select('*')
      .eq('id', eventId)
      .single()

    if (!event) return

    const detailsContainer = document.getElementById('eventDetails')
    detailsContainer.innerHTML = `
      <div class="event-detail-grid">
        <div class="event-detail-item">
          <div class="event-detail-label">Source IP</div>
          <div class="event-detail-value">${event.source_ip}</div>
        </div>
        <div class="event-detail-item">
          <div class="event-detail-label">Destination IP</div>
          <div class="event-detail-value">${event.destination_ip}</div>
        </div>
        <div class="event-detail-item">
          <div class="event-detail-label">Protocol</div>
          <div class="event-detail-value">${event.protocol}</div>
        </div>
        <div class="event-detail-item">
          <div class="event-detail-label">Port</div>
          <div class="event-detail-value">${event.port}</div>
        </div>
        <div class="event-detail-item">
          <div class="event-detail-label">Packet Size</div>
          <div class="event-detail-value">${event.packet_size} bytes</div>
        </div>
        <div class="event-detail-item">
          <div class="event-detail-label">Threat Level</div>
          <div class="event-detail-value">
            <span class="threat-badge ${event.threat_level}">${event.threat_level}</span>
          </div>
        </div>
        <div class="event-detail-item">
          <div class="event-detail-label">Status</div>
          <div class="event-detail-value">
            <span class="status-badge ${event.is_blocked ? 'blocked' : 'allowed'}">
              ${event.is_blocked ? 'Blocked' : 'Allowed'}
            </span>
          </div>
        </div>
        <div class="event-detail-item">
          <div class="event-detail-label">Description</div>
          <div class="event-detail-value">${event.description || 'N/A'}</div>
        </div>
        <div class="event-detail-item">
          <div class="event-detail-label">Timestamp</div>
          <div class="event-detail-value">${new Date(event.timestamp).toLocaleString()}</div>
        </div>
      </div>
    `

    this.showModal('eventModal')
  }

  async acknowledgeAlert(alertId) {
    await this.supabase
      .from('alerts')
      .update({
        status: 'acknowledged',
        acknowledged_at: new Date().toISOString()
      })
      .eq('id', alertId)

    this.updateAlerts()
  }

  async filterAlerts(filter) {
    let query = this.supabase
      .from('alerts')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(10)

    if (filter !== 'all') {
      if (filter === 'new') {
        query = query.eq('status', 'new')
      } else {
        query = query.eq('severity', filter)
      }
    }

    const { data: alerts } = await query
    this.renderAlerts(alerts || [])
  }

  renderAlerts(alerts) {
    const container = document.getElementById('alertsList')

    if (alerts.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
          </svg>
          <p>No alerts found</p>
        </div>
      `
      return
    }

    container.innerHTML = alerts.map(alert => `
      <div class="alert-item ${alert.severity}" onclick="window.uiManager.acknowledgeAlert('${alert.id}')">
        <div class="alert-header">
          <span class="alert-title">${alert.title}</span>
          <span class="alert-badge ${alert.severity}">${alert.severity}</span>
        </div>
        <p class="alert-message">${alert.message}</p>
        <span class="alert-time">${this.formatTime(alert.created_at)}</span>
      </div>
    `).join('')
  }

  searchEvents(searchTerm) {
    const rows = document.querySelectorAll('#eventsTable tr')
    const term = searchTerm.toLowerCase()

    rows.forEach(row => {
      const text = row.textContent.toLowerCase()
      row.style.display = text.includes(term) ? '' : 'none'
    })
  }

  showModal(modalId) {
    const modal = document.getElementById(modalId)
    modal.classList.add('active')

    if (modalId === 'blockIpModal') {
      this.loadBlockedIPs()
    }
  }

  hideModal(modalId) {
    const modal = document.getElementById(modalId)
    modal.classList.remove('active')
  }

  formatTime(timestamp) {
    const date = new Date(timestamp)
    const now = new Date()
    const diff = now - date

    if (diff < 60000) {
      return 'Just now'
    } else if (diff < 3600000) {
      return `${Math.floor(diff / 60000)}m ago`
    } else if (diff < 86400000) {
      return `${Math.floor(diff / 3600000)}h ago`
    } else {
      return date.toLocaleDateString() + ' ' + date.toLocaleTimeString()
    }
  }
}

if (typeof window !== 'undefined') {
  window.uiManager = null
  window.addEventListener('load', () => {
    const event = new Event('uiManagerReady')
    window.dispatchEvent(event)
  })
}
