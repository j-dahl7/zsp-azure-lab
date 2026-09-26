"""Bound SDK client lifetimes and keep synchronous cloud I/O off the event loop."""
import asyncio
from contextlib import asynccontextmanager, contextmanager
from functools import wraps


def in_worker_thread(operation):
    """Keep the async activity contract while offloading the complete sync call."""
    @wraps(operation)
    async def run(*args, **kwargs):
        return await asyncio.to_thread(operation, *args, **kwargs)
    return run


@contextmanager
def authorization_client(supplied, subscription_id):
    if supplied is not None:
        yield supplied
        return
    from azure.identity import ManagedIdentityCredential
    from azure.mgmt.authorization import AuthorizationManagementClient
    with ManagedIdentityCredential() as credential:
        with AuthorizationManagementClient(credential, subscription_id) as client:
            yield client


@asynccontextmanager
async def graph_client(supplied):
    if supplied is not None:
        yield supplied
        return
    from azure.identity.aio import ManagedIdentityCredential
    from kiota_authentication_azure.azure_identity_authentication_provider import AzureIdentityAuthenticationProvider
    from msgraph import GraphServiceClient
    from msgraph.graph_request_adapter import GraphRequestAdapter
    from msgraph_core import GraphClientFactory

    async with ManagedIdentityCredential() as credential:
        async with GraphClientFactory.create_with_default_middleware() as http_client:
            provider = AzureIdentityAuthenticationProvider(
                credential, allowed_hosts=['graph.microsoft.com'],
                scopes=['https://graph.microsoft.com/.default'],
            )
            yield GraphServiceClient(request_adapter=GraphRequestAdapter(provider, http_client))
