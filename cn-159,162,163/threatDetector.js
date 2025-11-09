export class ThreatDetector {
  constructor(supabase) {
    this.supabase = supabase
    this.threatPatterns = {
      portScan: [22, 23, 80, 443, 3389, 8080],
      suspiciousPorts: [1337, 31337, 4444, 5555],
      knownMaliciousPorts: [6667, 6668, 6669]
    }
  }

  async analyzeNetworkEvent(event) {
    const threats = []
    const threatLevel = this.calculateThreatLevel(event)

    if (this.isPortScan(event)) {
      threats.push('Port Scan Detected')
    }

    if (this.isSuspiciousPort(event.port)) {
      threats.push('Suspicious Port Activity')
    }

    if (this.isUnusualTraffic(event)) {
      threats.push('Unusual Traffic Pattern')
    }

    if (await this.isBlockedIP(event.source_ip)) {
      threats.push('Blocked IP Attempting Connection')
      return {
        threatLevel: 'critical',
        threatType: threats.join(', '),
        shouldBlock: true
      }
    }

    return {
      threatLevel,
      threatType: threats.length > 0 ? threats.join(', ') : null,
      shouldBlock: threatLevel === 'critical'
    }
  }

  calculateThreatLevel(event) {
    let score = 0

    if (this.threatPatterns.knownMaliciousPorts.includes(event.port)) {
      score += 40
    }

    if (this.threatPatterns.suspiciousPorts.includes(event.port)) {
      score += 30
    }

    if (event.packet_size > 10000) {
      score += 20
    }

    if (event.protocol === 'ICMP' && event.packet_size > 1000) {
      score += 25
    }

    if (this.isPrivateIP(event.destination_ip) && !this.isPrivateIP(event.source_ip)) {
      score += 15
    }

    if (score >= 70) return 'critical'
    if (score >= 50) return 'high'
    if (score >= 30) return 'medium'
    return 'low'
  }

  isPortScan(event) {
    return this.threatPatterns.portScan.includes(event.port) &&
           event.protocol === 'TCP'
  }

  isSuspiciousPort(port) {
    return this.threatPatterns.suspiciousPorts.includes(port) ||
           this.threatPatterns.knownMaliciousPorts.includes(port)
  }

  isUnusualTraffic(event) {
    return event.packet_size > 50000 ||
           (event.protocol === 'UDP' && event.port < 1024)
  }

  isPrivateIP(ip) {
    const parts = ip.split('.').map(Number)
    return (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168)
    )
  }

  async isBlockedIP(ip) {
    const { data } = await this.supabase
      .from('blocked_ips')
      .select('*')
      .eq('ip_address', ip)
      .eq('is_active', true)
      .maybeSingle()

    return data !== null
  }

  generateThreatDescription(threatType, event) {
    const descriptions = {
      'Port Scan Detected': `Possible port scanning activity detected from ${event.source_ip} targeting port ${event.port}`,
      'Suspicious Port Activity': `Connection attempt on suspicious port ${event.port} from ${event.source_ip}`,
      'Unusual Traffic Pattern': `Unusual traffic pattern detected: ${event.packet_size} bytes via ${event.protocol}`,
      'Blocked IP Attempting Connection': `Previously blocked IP ${event.source_ip} attempting to reconnect`
    }

    return descriptions[threatType] || `Security event detected from ${event.source_ip}`
  }
}
