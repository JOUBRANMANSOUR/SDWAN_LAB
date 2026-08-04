from __future__ import annotations
import tempfile
from pathlib import Path
import unittest
from fastapi.testclient import TestClient
from sdwan_v5.management.app import create_app
from sdwan_v5.management.config import ManagementConfig
from sdwan_v5.management.service import ManagementService
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
    def test_route_decision_report_is_deterministic_and_evidence_bounded(self):
        class Runtime:
            def routes(self, site):
                return {"availability":"AVAILABLE","value":[
                    {"dst":"10.2.0.0/24","table":1101,"dev":"wg-h1-mpls"},
                    {"dst":"198.18.0.10","table":102,"dev":"node1-bb","gateway":"192.168.20.254"},
                    {"dst":"fe80::/64","table":1101,"dev":"wg-h1-mpls"},
                ]}
            def route_lookup(self, site, destination, source=None, fwmark=None):
                return {"availability":"AVAILABLE","value":[{"dst":destination,"table":1101,"dev":"wg-h1-mpls"}]}
            def rules(self, site):
                return {"availability":"AVAILABLE","value":[
                    {"priority":1101,"fwmark":"0x1001","fwmask":"0x30ff","table":1101},
                    {"priority":2002,"fwmark":"0x2","fwmask":"0xff","table":102},
                ]}
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', '', '')
            service = ManagementService(config); service.runtime = Runtime()
            report = service.route_decision_report('node1', '10.2.0.10', fwmark=0x1001)
        self.assertTrue(report['available'])
        self.assertEqual(report['selected_routing_table'], 1101)
        self.assertEqual(report['matched_rule']['table'], 1101)
        self.assertEqual(report['output_interface'], 'wg-h1-mpls')
        self.assertEqual(report['derived']['hub'], 'hub1')
        self.assertIn('connection_mark', [item['field'] for item in report['unknowns']])

    def test_site_status_is_compact_configured_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            config = ManagementConfig(ROOT/'config/topology.yaml', Path(directory)/'policy.db', Path(directory)/'ztp.db', Path(directory), 'test-secret', '', '')
            service = ManagementService(config)
            status = service.site_status('node1')
        self.assertEqual(status['site'], 'node1')
        self.assertEqual(status['lan_prefix'], '10.1.0.0/24')
        self.assertEqual(status['preferred_hub'], 'hub1')
        self.assertNotIn('routes', status)
        self.assertNotIn('tunnels', status)

    def test_no_http_mcp_endpoint_and_session_ownership(self):
        with tempfile.TemporaryDirectory() as directory:
            client=self.app(directory); viewer={'Authorization':'Bearer '+self.token(client,'viewer')}; admin={'Authorization':'Bearer '+self.token(client,'admin')}
            self.assertEqual(client.post('/mcp',json={'method':'initialize','id':1}).status_code,404)
            session=client.post('/api/v1/chat/sessions',headers=viewer).json()['session_id']
            self.assertEqual(client.get('/api/v1/chat/sessions/%s'%session,headers=admin).status_code,404)
            self.assertEqual(client.get('/api/v1/dashboard/summary',headers=viewer).status_code,200)
