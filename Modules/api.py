import psutil
import secrets
import string
import time
import subprocess
from flask import Flask, jsonify, request

class API:
    def __init__(self):
        # Removed the API key generation and validation as it is not required now.
        self.network_traffic_data = {
            "sent": [],
            "recv": [],
        }

    def get_system_metrics(self, metric_name, duration):
        """Fetch system metrics based on the metric name over a given duration."""
        try:
            if metric_name == 'cpu_usage':
                return self.measure_cpu_usage(duration)
            elif metric_name == 'memory_usage':
                return self.measure_memory_usage(duration)
            elif metric_name == 'disk_usage':
                return self.measure_disk_usage(duration)
            elif metric_name == 'network_stats':
                return self.measure_network_stats(duration)
            elif metric_name == 'throughput':
                return self.measure_throughput(duration)
            elif metric_name == 'latency':
                return self.measure_latency(duration)
            elif metric_name == 'packet_drops':
                return self.measure_packet_drops(duration)
            else:
                return {"error": "Invalid metric name. Supported metrics: cpu_usage, memory_usage, disk_usage, network_stats, throughput, latency, packet_drops"}
        except Exception as e:
            return {"error": str(e)}

    def measure_cpu_usage(self, duration):
        """Measure CPU usage over the specified duration."""
        cpu_usages = []
        start_time = time.time()
        while time.time() - start_time < duration:
            cpu_usages.append(psutil.cpu_percent(interval=1))
        return {"cpu_usage_avg_percent": sum(cpu_usages) / len(cpu_usages)}

    def measure_memory_usage(self, duration):
        """Measure memory usage over the specified duration."""
        memory_usages = []
        start_time = time.time()
        while time.time() - start_time < duration:
            memory = psutil.virtual_memory()
            memory_usages.append(memory.percent)
            time.sleep(1)
        return {
            "memory_total": memory.total,
            "memory_used_avg_percent": sum(memory_usages) / len(memory_usages),
            "memory_free": memory.free,
            "memory_percent": memory.percent,
        }

    def measure_disk_usage(self, duration):
        """Measure disk usage over the specified duration."""
        disk_usages = []
        start_time = time.time()
        while time.time() - start_time < duration:
            disk = psutil.disk_usage('/')
            disk_usages.append(disk.percent)
            time.sleep(1)
        return {
            "disk_total": disk.total,
            "disk_used_avg_percent": sum(disk_usages) / len(disk_usages),
            "disk_free": disk.free,
            "disk_percent": disk.percent,
        }

    def measure_network_stats(self, duration):
        """Measure network stats over the specified duration."""
        network_stats = {
            "bytes_sent": 0,
            "bytes_recv": 0,
            "packets_sent": 0,
            "packets_recv": 0,
        }
        start_time = time.time()
        while time.time() - start_time < duration:
            network = psutil.net_io_counters()
            network_stats["bytes_sent"] += network.bytes_sent
            network_stats["bytes_recv"] += network.bytes_recv
            network_stats["packets_sent"] += network.packets_sent
            network_stats["packets_recv"] += network.packets_recv
            time.sleep(1)
        return network_stats

    def measure_throughput(self, duration):
        """Measure throughput over a custom duration and calculate rolling averages."""
        start_time = time.time()
        network_before = psutil.net_io_counters()

        total_sent = 0
        total_recv = 0
        while time.time() - start_time < duration:
            network_after = psutil.net_io_counters()
            total_sent += network_after.bytes_sent - network_before.bytes_sent
            total_recv += network_after.bytes_recv - network_before.bytes_recv
            network_before = network_after
            time.sleep(1)  # Wait for a second before measuring again

        # Calculate throughput averages
        avg_sent = total_sent / duration
        avg_recv = total_recv / duration

        return {
            "throughput_sent_avg_bytes_per_sec": avg_sent,
            "throughput_recv_avg_bytes_per_sec": avg_recv,
        }

    def measure_latency(self, duration):
        """Measure latency over a custom duration by pinging the localhost."""
        pings = []
        start_time = time.time()
        while time.time() - start_time < duration:
            ping_start = time.time()
            try:
                subprocess.check_call(['ping', '-c', '1', 'localhost'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except subprocess.CalledProcessError:
                continue  # Ignore ping failures
            ping_end = time.time()
            latency = (ping_end - ping_start) * 1000  # Convert to milliseconds
            pings.append(latency)
            time.sleep(1)  # Wait before sending the next ping
        
        if pings:
            return {"latency_avg_ms": sum(pings) / len(pings)}
        else:
            return {"error": "No successful pings to measure latency"}

    def measure_packet_drops(self, duration):
        """Measure packet drops over a custom duration."""
        start_time = time.time()
        packet_drops = 0
        while time.time() - start_time < duration:
            for iface in psutil.net_if_stats().values():
                packet_drops += iface.dropin + iface.dropout
            time.sleep(1)  # Wait for a second before measuring again

        return {"packet_drops": packet_drops}

    def handle_request(self, request):
        """Handle incoming API requests."""
        metric_name = request.args.get('metric')
        duration = request.args.get('duration', default=60, type=int)  # Default to 60 seconds if not specified

        if not metric_name:
            return jsonify({
                "error": "Metric parameter is required. Example: /api?metric=cpu_usage&duration=60"
            }), 400

        # Call appropriate metric function based on requested metric
        metric_data = self.get_system_metrics(metric_name, duration)
        return jsonify(metric_data)


api = API()
