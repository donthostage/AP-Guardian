--[[
LuCI CBI модель для настроек AP-Guardian
]]

m = Map("ap-guardian", translate("AP-Guardian Settings"), translate("Configure active network protection system"))

-- Общие настройки
s = m:section(TypedSection, "general", translate("General Settings"))
s.anonymous = true
s.addremove = false

enabled = s:option(Flag, "enabled", translate("Enable AP-Guardian"))
enabled.default = 1

log_level = s:option(ListValue, "log_level", translate("Log Level"))
log_level:value("DEBUG", "DEBUG")
log_level:value("INFO", "INFO")
log_level:value("WARNING", "WARNING")
log_level:value("ERROR", "ERROR")
log_level.default = "INFO"

log_file = s:option(Value, "log_file", translate("Log File"))
log_file.default = "/var/log/ap-guardian.log"

check_interval = s:option(Value, "check_interval", translate("Check Interval (seconds)"))
check_interval.datatype = "uinteger"
check_interval.default = "3"

-- ARP Spoofing настройки
s = m:section(TypedSection, "arp_spoofing", translate("ARP Spoofing Detection"))
s.anonymous = true
s.addremove = false

arp_enabled = s:option(Flag, "enabled", translate("Enable ARP Spoofing Detection"))
arp_enabled.default = 1

arp_check_interval = s:option(Value, "check_interval", translate("Check Interval (seconds)"))
arp_check_interval.datatype = "uinteger"
arp_check_interval.default = "3"

arp_threshold = s:option(Value, "threshold", translate("Conflict Threshold"))
arp_threshold.datatype = "uinteger"
arp_threshold.default = "3"
arp_threshold.description = translate("Number of MAC changes before alert")

arp_block_duration = s:option(Value, "block_duration", translate("Block Duration (seconds)"))
arp_block_duration.datatype = "uinteger"
arp_block_duration.default = "3600"

monitor_gateway = s:option(Flag, "monitor_gateway", translate("Monitor Gateway"))
monitor_gateway.default = 1
monitor_gateway.description = translate("Monitor gateway IP for ARP spoofing")

trusted_devices = s:option(DynamicList, "trusted_devices", translate("Trusted Devices"))
trusted_devices.description = translate("List of trusted IP addresses (one per line)")

-- DDoS настройки
s = m:section(TypedSection, "ddos", translate("DDoS Protection"))
s.anonymous = true
s.addremove = false

ddos_enabled = s:option(Flag, "enabled", translate("Enable DDoS Detection"))
ddos_enabled.default = 1

adaptive_thresholds = s:option(Flag, "adaptive_thresholds", translate("Adaptive Thresholds"))
adaptive_thresholds.default = 1
adaptive_thresholds.description = translate("Automatically adjust thresholds based on normal traffic")

-- SYN Flood
s = m:section(TypedSection, "syn_flood", translate("SYN Flood Detection"))
s.anonymous = true
s.addremove = false

syn_enabled = s:option(Flag, "enabled", translate("Enable SYN Flood Detection"))
syn_enabled.default = 1

syn_threshold = s:option(Value, "syn_per_second_threshold", translate("SYN Packets/Second Threshold"))
syn_threshold.datatype = "uinteger"
syn_threshold.default = "100"

syn_ack_ratio = s:option(Value, "syn_ack_ratio_threshold", translate("SYN-ACK Ratio Threshold"))
syn_ack_ratio.datatype = "float"
syn_ack_ratio.default = "0.1"

incomplete_connections = s:option(Value, "incomplete_connections_threshold", translate("Incomplete Connections Threshold"))
incomplete_connections.datatype = "uinteger"
incomplete_connections.default = "50"

-- UDP Flood
s = m:section(TypedSection, "udp_flood", translate("UDP Flood Detection"))
s.anonymous = true
s.addremove = false

udp_enabled = s:option(Flag, "enabled", translate("Enable UDP Flood Detection"))
udp_enabled.default = 1

udp_threshold = s:option(Value, "packets_per_second_threshold", translate("Packets/Second Threshold"))
udp_threshold.datatype = "uinteger"
udp_threshold.default = "1000"

udp_anomaly = s:option(Flag, "anomaly_detection", translate("Anomaly Detection"))
udp_anomaly.default = 1

-- ICMP Flood
s = m:section(TypedSection, "icmp_flood", translate("ICMP Flood Detection"))
s.anonymous = true
s.addremove = false

icmp_enabled = s:option(Flag, "enabled", translate("Enable ICMP Flood Detection"))
icmp_enabled.default = 1

icmp_threshold = s:option(Value, "packets_per_second_threshold", translate("Packets/Second Threshold"))
icmp_threshold.datatype = "uinteger"
icmp_threshold.default = "500"

icmp_anomaly = s:option(Flag, "anomaly_detection", translate("Anomaly Detection"))
icmp_anomaly.default = 1

-- Network Scan настройки
s = m:section(TypedSection, "network_scan", translate("Network Scan Detection"))
s.anonymous = true
s.addremove = false

scan_enabled = s:option(Flag, "enabled", translate("Enable Network Scan Detection"))
scan_enabled.default = 1

-- Horizontal Scan
s = m:section(TypedSection, "horizontal_scan", translate("Horizontal Scan Detection"))
s.anonymous = true
s.addremove = false

horizontal_enabled = s:option(Flag, "enabled", translate("Enable Horizontal Scan Detection"))
horizontal_enabled.default = 1

horizontal_hosts = s:option(Value, "hosts_threshold", translate("Hosts Threshold"))
horizontal_hosts.datatype = "uinteger"
horizontal_hosts.default = "10"

horizontal_window = s:option(Value, "time_window", translate("Time Window (seconds)"))
horizontal_window.datatype = "uinteger"
horizontal_window.default = "60"

-- Vertical Scan
s = m:section(TypedSection, "vertical_scan", translate("Vertical Scan Detection"))
s.anonymous = true
s.addremove = false

vertical_enabled = s:option(Flag, "enabled", translate("Enable Vertical Scan Detection"))
vertical_enabled.default = 1

vertical_ports = s:option(Value, "ports_threshold", translate("Ports Threshold"))
vertical_ports.datatype = "uinteger"
vertical_ports.default = "20"

vertical_window = s:option(Value, "time_window", translate("Time Window (seconds)"))
vertical_window.datatype = "uinteger"
vertical_window.default = "60"

-- Firewall настройки
s = m:section(TypedSection, "firewall", translate("Firewall Management"))
s.anonymous = true
s.addremove = false

fw_enabled = s:option(Flag, "enabled", translate("Enable Firewall Management"))
fw_enabled.default = 1

auto_block = s:option(Flag, "auto_block", translate("Automatic Blocking"))
auto_block.default = 1
auto_block.description = translate("Automatically block detected threats")

rate_limit = s:option(Flag, "rate_limit", translate("Enable Rate Limiting"))
rate_limit.default = 1

rate_limit_packets = s:option(Value, "rate_limit_packets", translate("Rate Limit Packets"))
rate_limit_packets.datatype = "uinteger"
rate_limit_packets.default = "100"

rate_limit_seconds = s:option(Value, "rate_limit_seconds", translate("Rate Limit Seconds"))
rate_limit_seconds.datatype = "uinteger"
rate_limit_seconds.default = "1"

whitelist = s:option(DynamicList, "whitelist", translate("Whitelist"))
whitelist.description = translate("IP addresses that will never be blocked")

blacklist = s:option(DynamicList, "blacklist", translate("Blacklist"))
blacklist.description = translate("IP addresses that will always be blocked")

return m
