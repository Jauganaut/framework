#!/usr/bin/env python3
"""
Session Manager - Handles Docker container lifecycle
"""

import socket
from typing import Dict
from docker.errors import NotFound


class SessionManager:
    def __init__(self, docker_client, config: Dict):
        self.docker = docker_client
        self.config = config
        self._port_pool = set(range(5900, 6900))
        self._allocated_ports = set()
        self._ensure_network()

    def _ensure_network(self):
        try:
            self.docker.networks.get('bitb_net')
        except NotFound:
            self.docker.networks.create('bitb_net', driver='bridge', internal=False)

    def reserve_port(self) -> int:
        available = self._port_pool - self._allocated_ports
        if not available:
            raise RuntimeError('No ports available')
        port = min(available)
        self._allocated_ports.add(port)
        return port

    def release_port(self, port: int):
        self._allocated_ports.discard(port)

    def get_container_logs(self, container_id: str, tail: int = 100) -> str:
        try:
            container = self.docker.containers.get(container_id)
            return container.logs(tail=tail).decode('utf-8')
        except Exception as e:
            return f'Error getting logs: {e}'

    def cleanup_stopped(self):
        for container in self.docker.containers.list(all=True, filters={'status': 'exited'}):
            if container.name.startswith('firefox_'):
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def get_stats(self, container_id: str) -> Dict:
        try:
            container = self.docker.containers.get(container_id)
            stats = container.stats(stream=False)
            return {
                'cpu_usage': stats['cpu_stats'].get('cpu_usage', {}).get('total_usage', 0),
                'memory_usage': stats['memory_stats'].get('usage', 0),
                'memory_limit': stats['memory_stats'].get('limit', 0),
            }
        except Exception as e:
            return {'error': str(e)}
