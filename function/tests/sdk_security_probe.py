"""Run with the actual hash-locked SDKs; transport is entirely in memory."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import types
import asyncio
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# Binding/transport probe isolates unrelated Graph/RBAC SDK imports. CI also
# imports the entire actual runtime separately in its hash-locked environment.
for module_name, names in {
    'admin_access': ['ensure_admin_entitlement_absent', 'grant_admin_access', 'revoke_admin_access'],
    'nhi_access': ['ensure_nhi_entitlement_absent', 'grant_nhi_access', 'revoke_nhi_access'],
}.items():
    module = types.ModuleType(module_name)
    for name in names:
        setattr(module, name, None)
    module.ROLE_DEFINITIONS = {}
    sys.modules[module_name] = module
import function_app
from azure.core.credentials import AccessToken
from azure.core.exceptions import HttpResponseError
from azure.core.pipeline.transport import HttpTransport, HttpResponse
from azure.monitor.ingestion import LogsIngestionClient
from azure.durable_functions.models.DurableOrchestrationStatus import DurableOrchestrationStatus
from azure.durable_functions.models.OrchestrationRuntimeStatus import OrchestrationRuntimeStatus
from client_lifecycle import graph_client as managed_graph_client


async def verify_managed_graph_lifetime():
    # Construct and close the actual Graph adapter without requesting a token
    # or sending HTTP. This catches SDK factory/signature incompatibilities.
    from msgraph_core import GraphClientFactory
    created_credentials = []
    created_clients = []
    factory = GraphClientFactory.create_with_default_middleware

    class NoNetworkCredential:
        def __init__(self): self.closed = False; created_credentials.append(self)
        async def __aenter__(self): return self
        async def __aexit__(self, *args): self.closed = True
        async def get_token(self, *args, **kwargs): raise AssertionError('No token request is allowed')

    def recorded_factory(*args, **kwargs):
        client = factory(*args, **kwargs)
        created_clients.append(client)
        return client

    with patch('azure.identity.aio.ManagedIdentityCredential', NoNetworkCredential), \
         patch.object(GraphClientFactory, 'create_with_default_middleware', recorded_factory):
        async with managed_graph_client(None) as graph:
            assert graph.groups is not None
    assert created_credentials[0].closed
    assert created_clients[0].is_closed


asyncio.run(verify_managed_graph_lifetime())

bindings = {item.get_function_name(): item.get_bindings_dict()['bindings'] for item in function_app.app.get_functions()}
assert 'access_lifecycle_orchestrator' not in bindings
assert 'revocation_orchestrator' not in bindings
assert any(item['type'] == 'orchestrationTrigger' for item in bindings['access_lifecycle_orchestrator_v2'])
route = next(item for item in bindings['access_status'] if item['type'] == 'httpTrigger')
assert route['route'] == 'api/access-status/{instance_id}' and str(route['authLevel']).casefold() == 'function', repr(route)
assert [str(method).upper() for method in route['methods']] == ['GET'], repr(route)
assert json.loads((Path(__file__).resolve().parents[1] / 'host.json').read_text())['extensions']['http']['routePrefix'] == ''
status = DurableOrchestrationStatus(name='access_lifecycle_orchestrator_v2', instanceId='instance-123',
    createdTime='2026-09-05T00:00:00Z', lastUpdatedTime='2026-09-05T00:00:00Z', input={'api_version': 2}, runtimeStatus=OrchestrationRuntimeStatus.Running)
assert status and status.to_json()['input'] == {'api_version': 2}
assert status.to_json()['runtimeStatus'] == 'Running'

class Credential:
    def get_token(self, *scopes, **kwargs):
        assert scopes == ('https://monitor.azure.com/.default',)
        return AccessToken('synthetic-test-token', int(datetime.now(timezone.utc).timestamp()) + 3600)

class RedirectResponse(HttpResponse):
    def __init__(self, request):
        super().__init__(request, None)
        self.status_code = 307
        self.headers = {'Location': 'https://attacker.example/collect', 'Content-Type': 'application/json'}
        self.reason = 'Temporary Redirect'
        self.content_type = 'application/json'
    def body(self):
        return b'{}'

class Transport(HttpTransport):
    def __init__(self): self.requests = []
    def open(self): pass
    def close(self): pass
    def __enter__(self): return self
    def __exit__(self, *args): self.close()
    def send(self, request, **kwargs):
        self.requests.append(request)
        return RedirectResponse(request)

transport = Transport()
client = LogsIngestionClient('https://example-dce.eastus-1.ingest.monitor.azure.com', Credential(),
                            permit_redirects=False, retry_total=0, transport=transport)
try:
    client.upload(rule_id='dcr-' + '0' * 32, stream_name='Custom-ZSPAudit_CL', logs=[{'EventType': 'offline-test'}])
except HttpResponseError:
    pass
else:
    raise AssertionError('307 must fail closed')
assert len(transport.requests) == 1, 'A redirect must never forward a managed-identity token'
assert transport.requests[0].url.startswith('https://example-dce.eastus-1.ingest.monitor.azure.com/')
assert transport.requests[0].headers['Authorization'] == 'Bearer synthetic-test-token'
client.close()
print('Real SDK route registration, status schema, and no-redirect credential transport passed.')
