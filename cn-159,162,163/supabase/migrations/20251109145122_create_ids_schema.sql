/*
  # AI-based Intrusion Detection System Schema

  1. New Tables
    - `network_events`
      - `id` (uuid, primary key)
      - `timestamp` (timestamptz) - When the event occurred
      - `source_ip` (text) - Source IP address
      - `destination_ip` (text) - Destination IP address
      - `protocol` (text) - Network protocol (TCP, UDP, ICMP, etc.)
      - `port` (integer) - Port number
      - `packet_size` (integer) - Size of the packet in bytes
      - `threat_level` (text) - low, medium, high, critical
      - `threat_type` (text) - Type of threat detected
      - `is_blocked` (boolean) - Whether the threat was blocked
      - `description` (text) - Event description
      - `created_at` (timestamptz)

    - `alerts`
      - `id` (uuid, primary key)
      - `event_id` (uuid, foreign key to network_events)
      - `severity` (text) - low, medium, high, critical
      - `title` (text) - Alert title
      - `message` (text) - Alert message
      - `status` (text) - new, acknowledged, resolved
      - `acknowledged_at` (timestamptz)
      - `resolved_at` (timestamptz)
      - `created_at` (timestamptz)

    - `blocked_ips`
      - `id` (uuid, primary key)
      - `ip_address` (text, unique) - Blocked IP address
      - `reason` (text) - Reason for blocking
      - `blocked_at` (timestamptz)
      - `expires_at` (timestamptz) - When the block expires (null for permanent)
      - `is_active` (boolean) - Whether the block is currently active

    - `network_stats`
      - `id` (uuid, primary key)
      - `timestamp` (timestamptz) - Time of the stat collection
      - `total_traffic` (bigint) - Total traffic in bytes
      - `active_connections` (integer) - Number of active connections
      - `threats_detected` (integer) - Number of threats detected
      - `threats_blocked` (integer) - Number of threats blocked

  2. Security
    - Enable RLS on all tables
    - Add policies for public read access (campus network monitoring dashboard)
    - Add policies for authenticated insert/update operations
*/

-- Create network_events table
CREATE TABLE IF NOT EXISTS network_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp timestamptz DEFAULT now(),
  source_ip text NOT NULL,
  destination_ip text NOT NULL,
  protocol text NOT NULL,
  port integer NOT NULL,
  packet_size integer DEFAULT 0,
  threat_level text DEFAULT 'low',
  threat_type text,
  is_blocked boolean DEFAULT false,
  description text,
  created_at timestamptz DEFAULT now()
);

-- Create alerts table
CREATE TABLE IF NOT EXISTS alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid REFERENCES network_events(id) ON DELETE CASCADE,
  severity text NOT NULL DEFAULT 'low',
  title text NOT NULL,
  message text NOT NULL,
  status text DEFAULT 'new',
  acknowledged_at timestamptz,
  resolved_at timestamptz,
  created_at timestamptz DEFAULT now()
);

-- Create blocked_ips table
CREATE TABLE IF NOT EXISTS blocked_ips (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_address text UNIQUE NOT NULL,
  reason text NOT NULL,
  blocked_at timestamptz DEFAULT now(),
  expires_at timestamptz,
  is_active boolean DEFAULT true
);

-- Create network_stats table
CREATE TABLE IF NOT EXISTS network_stats (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  timestamp timestamptz DEFAULT now(),
  total_traffic bigint DEFAULT 0,
  active_connections integer DEFAULT 0,
  threats_detected integer DEFAULT 0,
  threats_blocked integer DEFAULT 0
);

-- Enable RLS
ALTER TABLE network_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE blocked_ips ENABLE ROW LEVEL SECURITY;
ALTER TABLE network_stats ENABLE ROW LEVEL SECURITY;

-- RLS Policies for network_events
CREATE POLICY "Public can view network events"
  ON network_events FOR SELECT
  TO anon, authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert network events"
  ON network_events FOR INSERT
  TO authenticated
  WITH CHECK (true);

-- RLS Policies for alerts
CREATE POLICY "Public can view alerts"
  ON alerts FOR SELECT
  TO anon, authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert alerts"
  ON alerts FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "Authenticated users can update alerts"
  ON alerts FOR UPDATE
  TO authenticated
  USING (true)
  WITH CHECK (true);

-- RLS Policies for blocked_ips
CREATE POLICY "Public can view blocked IPs"
  ON blocked_ips FOR SELECT
  TO anon, authenticated
  USING (true);

CREATE POLICY "Authenticated users can manage blocked IPs"
  ON blocked_ips FOR INSERT
  TO authenticated
  WITH CHECK (true);

CREATE POLICY "Authenticated users can update blocked IPs"
  ON blocked_ips FOR UPDATE
  TO authenticated
  USING (true)
  WITH CHECK (true);

-- RLS Policies for network_stats
CREATE POLICY "Public can view network stats"
  ON network_stats FOR SELECT
  TO anon, authenticated
  USING (true);

CREATE POLICY "Authenticated users can insert network stats"
  ON network_stats FOR INSERT
  TO authenticated
  WITH CHECK (true);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_network_events_timestamp ON network_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_network_events_threat_level ON network_events(threat_level);
CREATE INDEX IF NOT EXISTS idx_network_events_source_ip ON network_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_blocked_ips_active ON blocked_ips(is_active) WHERE is_active = true;