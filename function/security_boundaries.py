"""Pure destination and identifier validation for credential-bearing paths."""
import re
from urllib.parse import urlsplit


INSTANCE_ID = re.compile(r'[A-Za-z0-9_-]{1,100}')
FUNCTION_HOST = re.compile(r'[a-z0-9-]+(?:\.[a-z0-9-]+)*\.azurewebsites\.net')
INGESTION_HOST = re.compile(r'[a-z0-9-]+\.[a-z0-9-]+\.ingest\.monitor\.azure\.com')


def validate_instance_id(value):
    if not isinstance(value, str) or not INSTANCE_ID.fullmatch(value):
        raise ValueError('Invalid lifecycle instance ID')
    return value


def status_origin(hostname, request_url='', *, development=False):
    """Use the platform hostname, never an arbitrary forwarded/request host."""
    if isinstance(hostname, str) and FUNCTION_HOST.fullmatch(hostname.lower()):
        return f'https://{hostname.lower()}'
    if development:
        parsed = urlsplit(request_url)
        if parsed.scheme in {'http', 'https'} and parsed.hostname in {'localhost', '127.0.0.1', '::1'} and not parsed.username and not parsed.password:
            return f'{parsed.scheme}://{parsed.netloc}'
    raise ValueError('A trusted Azure Function hostname is required for lifecycle status URLs')


def ingestion_endpoint(value):
    parsed = urlsplit(value)
    try:
        valid_port = parsed.port in (None, 443)
    except ValueError:
        valid_port = False
    if (parsed.scheme != 'https' or not parsed.hostname or
            not INGESTION_HOST.fullmatch(parsed.hostname) or not valid_port or
            parsed.username or parsed.password or parsed.path not in ('', '/') or
            parsed.query or parsed.fragment or '%' in parsed.netloc):
        raise ValueError('DCR_ENDPOINT must be a public Azure Monitor ingestion origin without credentials, path, query, or fragment')
    return f'https://{parsed.hostname}'


def immutable_dcr_id(value):
    if not isinstance(value, str) or not re.fullmatch(r'dcr-[a-fA-F0-9]{32}', value):
        raise ValueError('DCR_RULE_ID must be an immutable dcr- ID with 32 hexadecimal characters')
    return value.lower()
