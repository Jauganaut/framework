#!/usr/bin/env python3
"""
Cloudflare Tunnel Manager using the cloudflared binary provided through pycloudflared-style tooling.
"""

import asyncio
import os
import subprocess
import re
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class Tunnel:
    id: str
    url: str
    local_port: int
    process: Optional[subprocess.Popen] = None


class CloudflareTunnelManager:
    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.tunnels: Dict[str, Tunnel] = {}

    def _ensure_cloudflared(self):
        try:
            subprocess.run(['cloudflared', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError('cloudflared is not installed')

    async def create_tunnel(self, name: str, local_service: str) -> Dict:
        self._ensure_cloudflared()

        cmd = [
            'cloudflared', 'tunnel', '--url', f'http://{local_service}', '--metrics', 'localhost:0', '--no-autoupdate'
        ]
        if self.token:
            cmd = ['cloudflared', 'tunnel', 'run', '--token', self.token, '--url', f'http://{local_service}']

        env = os.environ.copy()
        env.setdefault('TUNNEL_METRICS', 'localhost:0')

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env
        )

        url = None
        tunnel_id = None
        stderr_output = []

        for _ in range(60):
            await asyncio.sleep(1)
            if process.stderr:
                line = process.stderr.readline()
                if line:
                    stderr_output.append(line)
                    if 'trycloudflare.com' in line:
                        match = re.search(r'https://[a-z0-9-]+\.trycloudflare\.com', line)
                        if match:
                            url = match.group(0)
                            tunnel_id = name
                            break

        if not url:
            process.terminate()
            if process.poll() is None:
                process.wait(timeout=5)
            combined_output = ''.join(stderr_output)
            raise RuntimeError(f'Failed to create tunnel. Output: {combined_output}')

        tunnel = Tunnel(
            id=tunnel_id,
            url=url,
            local_port=int(local_service.split(':')[-1]),
            process=process
        )
        self.tunnels[tunnel_id] = tunnel
        return {'id': tunnel_id, 'url': url, 'local_service': local_service}

    def delete_tunnel(self, tunnel_id: str):
        if tunnel_id in self.tunnels:
            tunnel = self.tunnels[tunnel_id]
            if tunnel.process:
                tunnel.process.terminate()
                tunnel.process.wait(timeout=5)
            del self.tunnels[tunnel_id]

    def get_tunnel_status(self, tunnel_id: str) -> Dict:
        if tunnel_id not in self.tunnels:
            return {'exists': False}
        tunnel = self.tunnels[tunnel_id]
        return {
            'exists': True,
            'url': tunnel.url,
            'running': tunnel.process.poll() is None if tunnel.process else False
        }

    def cleanup_all(self):
        for tunnel_id in list(self.tunnels.keys()):
            self.delete_tunnel(tunnel_id)
