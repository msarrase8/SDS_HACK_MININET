# SDS Project - HoneypotController.py

This Ryu controller combines L2 switching, traffic monitoring (for InfluxDB/Grafana), and placeholders for port scan detection and honeypot redirection logic.

## Features

1.  **Layer 2 Learning Switch:** Learns MAC addresses and installs flows for efficient L2 forwarding. ARPs are flooded.
2.  **Traffic Monitoring:**
    * Periodically polls connected OpenFlow switches for Port Statistics and Flow Statistics.
    * Formats these statistics into InfluxDB line protocol.
    * Sends the formatted statistics via UDP to a Telegraf agent.
3.  **Security Logic Placeholders:**
    * Basic structure for IP blocking (`self.blocked_ips`).
    * Example data structures for honeypot definitions (`self.honeypots`) and redirection triggers (`self.redirect_targets`).
    * Example data structures for rudimentary port scan detection (`self.port_activity`).
    * **Note:** The actual implementation of port scan detection and honeypot redirection flow installation (especially determining output ports for redirection in a multi-switch topology) needs to be completed by the team.

## Prerequisites for Monitoring

1.  **InfluxDB:** Installed and running on the same host as Ryu.
    * A database must be created (e.g., `RYU`).
2.  **Telegraf:** Installed and running on the same host as Ryu.
    * `telegraf.conf` must be configured with:
        * An `[[inputs.socket_listener]]` to listen on UDP (default in this controller: `udp://127.0.0.1:8094`) with `data_format = "influx"`.
        * An `[[outputs.influxdb]]` section pointing to your InfluxDB instance (e.g., `urls = ["http://127.0.0.1:8086"]`) and the correct database (e.g., `database = "RYU"`).

## Controller Configuration (Inside the Python script)

Before running, you may need to adjust these constants/attributes at the top of the `HoneypotController` class or in `__init__`:

1.  **`TELEGRAF_UDP_IP` and `TELEGRAF_UDP_PORT`:**
    * Default: `127.0.0.1` and `8094`.
    * Ensure these match your Telegraf `socket_listener` configuration.

2.  **InfluxDB Line Protocol Formats:**
    * `FLOW_STATS_MSG_FORMAT`
    * `PORT_STATS_MSG_FORMAT`
    * These define the measurement names, tags, and fields sent to InfluxDB. The current setup uses:
        * Measurement `sds_flow_stats`: tags `datapath_id, in_port, eth_dst`; fields `out_port, packets, bytes`.
        * Measurement `sds_port_stats`: tags `datapath_id, port_no`; fields `rx_pkts, rx_bytes, rx_errors, tx_pkts, tx_bytes, tx_errors`.
    * Numeric fields are sent as integers (e.g., `packets=10i`). String fields are quoted (e.g., `out_port="fffffffb"`).

3.  **Honeypot Definitions (for your team's logic):**
    * `self.honeypots`: Update with actual IPs/MACs of your honeypot hosts in `MyTopo.py`.
    * `self.redirect_targets`: Define which destination IPs, if targeted, should trigger a redirection to a specific honeypot.

## Running the Controller

```bash
ryu-manager HoneypotController.py --verbose