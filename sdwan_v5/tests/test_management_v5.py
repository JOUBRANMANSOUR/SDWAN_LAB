from __future__ import annotations
import tempfile
from pathlib import Path
import unittest
from fastapi.testclient import TestClient
from sdwan_v5.management.app import create_app
from sdwan_v5.management.config import ManagementConfig
ROOT = Path(__file__).resolve().parents[1]
class ManagementTests(unittest.TestCase):
    def app(self, directory):
        return TestClient(create_app(ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', 'viewer:pw:VIEWER,admin:pw:PLATFORM_ADMIN', '')))
    def token(self, client, user):
        return client.post('/api/v1/auth/login', json={'username':user,'password':'pw'}).json()['access_token']
    def test_viewer_reads_health_but_not_routes(self):
        with tempfile.TemporaryDirectory() as directory:
            client=self.app(directory); headers={'Authorization':'Bearer '+self.token(client,'viewer')}
            health=client.get('/api/v1/system/health',headers=headers); self.assertEqual(health.status_code,200); self.assertIn('X-Request-ID',health.headers)
            self.assertEqual(client.get('/api/v1/audit',headers=headers).status_code,403)
    def test_platform_admin_chat_is_persisted_and_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            client=self.app(directory); headers={'Authorization':'Bearer '+self.token(client,'admin')}
            session=client.post('/api/v1/chat/sessions',headers=headers).json()['session_id']
            from unittest.mock import patch
            async def fake_run(*args, **kwargs):
                from sdwan_v5.management.agent import AgentEvent
                yield AgentEvent('assistant_delta', {'text':'read-only status'})
                yield AgentEvent('agent_completed', {})
            with patch('sdwan_v5.management.app.OllamaClaudeRunner.run', fake_run):
                response=client.post('/api/v1/chat/sessions/%s/messages'%session,headers=headers,json={'message':'status'})
            self.assertEqual(response.status_code,202); self.assertTrue(response.json()['accepted'])
            self.assertEqual(len(client.get('/api/v1/chat/sessions/%s'%session,headers=headers).json()),2)
            self.assertTrue(client.get('/api/v1/audit',headers=headers).json())
    def test_no_http_mcp_endpoint_and_session_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            client=self.app(directory); viewer={'Authorization':'Bearer '+self.token(client,'viewer')}; admin={'Authorization':'Bearer '+self.token(client,'admin')}
            self.assertEqual(client.post('/mcp',json={'method':'initialize','id':1}).status_code,404)
            session=client.post('/api/v1/chat/sessions',headers=viewer).json()['session_id']
            self.assertEqual(client.get('/api/v1/chat/sessions/%s'%session,headers=admin).status_code,404)
            self.assertEqual(client.get('/api/v1/dashboard/summary',headers=viewer).status_code,200)
