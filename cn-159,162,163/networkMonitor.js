export class NetworkMonitor {
  constructor(supabase, threatDetector) {
    this.supabase = supabase
    this.threatDetector = threatDetector
    this.isRunning = false
    this.stats = {
      totalTraffic: 0,
      activeConnections: 0,
      threatsDetected: 0,
      threatsBlocked: 0
    }
  }

  start() {
    if (this.isRunning) return
    this.isRunning = true

    this.simulateNetworkTraffic()
    this.updateStatsInterval = setInterval(() => {
      this.updateStats()
    }, 10000)
  }

  stop() {
    this.isRunning = false
    if (this.updateStatsInterval) {
      clearInterval(this.updateStatsInterval)
    }
  }

  async simulateNetworkTraffic() {
    const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
    const commonPorts = [80, 443, 22, 21, 25, 3306, 5432, 8080]
    const suspiciousPorts = [1337, 4444, 5555, 31337]

    const generateIP = () => {
      const ranges = [
        () => `192.168.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        () => `10.0.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        () => `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
      ]
      return ranges[Math.floor(Math.random() * ranges.length)]()
    }

    const generateEvent = () => {
      const isThreat = Math.random() < 0.15
      const port = isThreat && Math.random() < 0.5
        ? suspiciousPorts[Math.floor(Math.random() * suspiciousPorts.length)]
        : commonPorts[Math.floor(Math.random() * commonPorts.length)]

      return {
        source_ip: generateIP(),
        destination_ip: generateIP(),
        protocol: protocols[Math.floor(Math.random() * protocols.length)],
        port: port,
        packet_size: Math.floor(Math.random() * (isThreat ? 100000 : 10000)) + 64,
        timestamp: new Date().toISOString()
      }
    }

    const processEvent = async () => {
      if (!this.isRunning) return

      const event = generateEvent()
      const analysis = await this.threatDetector.analyzeNetworkEvent(event)

      const networkEvent = {
        ...event,
        threat_level: analysis.threatLevel,
        threat_type: analysis.threatType,
        is_blocked: analysis.shouldBlock,
        description: analysis.threatType
          ? this.threatDetector.generateThreatDescription(analysis.threatType.split(',')[0], event)
          : `Normal ${event.protocol} traffic from ${event.source_ip}`
      }

      const { data: insertedEvent, error } = await this.supabase
        .from('network_events')
        .insert([networkEvent])
        .select()
        .single()

      if (!error && analysis.threatType) {
        this.stats.threatsDetected++
        if (analysis.shouldBlock) {
          this.stats.threatsBlocked++
        }

        await this.createAlert(insertedEvent, analysis)
      }

      this.stats.totalTraffic += event.packet_size
      this.stats.activeConnections = Math.floor(Math.random() * 500) + 100

      setTimeout(processEvent, Math.random() * 3000 + 1000)
    }

    processEvent()
  }

  async createAlert(event, analysis) {
    const severityMap = {
      'critical': 'critical',
      'high': 'high',
      'medium': 'medium',
      'low': 'low'
    }

    const alert = {
      event_id: event.id,
      severity: severityMap[analysis.threatLevel],
      title: analysis.threatType || 'Security Alert',
      message: event.description,
      status: 'new'
    }

    await this.supabase
      .from('alerts')
      .insert([alert])
  }

  async updateStats() {
    await this.supabase
      .from('network_stats')
      .insert([{
        total_traffic: this.stats.totalTraffic,
        active_connections: this.stats.activeConnections,
        threats_detected: this.stats.threatsDetected,
        threats_blocked: this.stats.threatsBlocked
      }])
  }

  async getRecentEvents(limit = 50) {
    const { data, error } = await this.supabase
      .from('network_events')
      .select('*')
      .order('timestamp', { ascending: false })
      .limit(limit)

    return data || []
  }

  async getRecentAlerts(limit = 10) {
    const { data, error } = await this.supabase
      .from('alerts')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(limit)

    return data || []
  }

  getStats() {
    return this.stats
  }
}
