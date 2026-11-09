"""Account-scoped Cloudflare provisioning. Bootstrap tokens never reach disk."""
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from .common import SetupError, require

API = 'https://api.cloudflare.com/client/v4'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise SetupError('Cloudflare API redirect refused')


class Cloudflare:
    def __init__(self, account, token, transport=None):
        require(bool(re.fullmatch('[a-fA-F0-9]{32}', account)), 'Invalid Cloudflare account ID')
        require(token and not any(c.isspace() for c in token), 'Invalid bootstrap token')
        self.account = account.lower()
        self._token = token
        self._transport = transport or urllib.request.build_opener(NoRedirect()).open

    def request(self, method, path, body=None, *, allow_not_found=False):
        require(path.startswith(f'/accounts/{self.account}/') and '..' not in path,
                'Refusing a request outside the chosen account')
        request = urllib.request.Request(API + path, method=method,
                                         data=None if body is None else json.dumps(body).encode(),
                                         headers={'Authorization': 'Bearer ' + self._token,
                                                  'Content-Type': 'application/json',
                                                  'User-Agent': 'cloudflare-disk-setup'})
        try:
            with self._transport(request, timeout=30) as response:
                raw = response.read(2 * 1024**2 + 1)
                require(len(raw) <= 2 * 1024**2, 'Cloudflare API response too large')
                value = json.loads(raw)
        except urllib.error.HTTPError as error:
            code = error.code
            error.close()
            if allow_not_found and code == 404:
                return None
            # Never print response bodies: a token endpoint may echo secret values.
            raise SetupError(f'Cloudflare {method} failed (HTTP {code}); check account permissions and R2 activation') from None
        except (OSError, ValueError) as error:
            raise SetupError('Cloudflare request failed or returned invalid JSON; inspect the dashboard before retrying a create') from error
        require(isinstance(value, dict) and value.get('success') is True, 'Cloudflare did not confirm the operation')
        return value.get('result')

    def permission_groups(self):
        groups = []
        for name in ['Workers R2 Storage Bucket Item Read', 'Workers R2 Storage Bucket Item Write']:
            result = self.request('GET', f'/accounts/{self.account}/tokens/permission_groups?'
                                  + urllib.parse.urlencode({'name': name}))
            require(isinstance(result, list), 'Invalid Cloudflare permission-group response')
            matches = [g for g in result if g.get('name') == name
                       and 'com.cloudflare.edge.r2.bucket' in g.get('scopes', [])
                       and g.get('is_selectable', True)]
            require(len(matches) == 1 and re.fullmatch('[a-fA-F0-9]{32}', matches[0].get('id', '')),
                    'Bootstrap token cannot grant the required R2 object permission')
            groups.append({'id': matches[0]['id']})
        return groups

    def bucket(self, name):
        return self.request('GET', f'/accounts/{self.account}/r2/buckets/{name}', allow_not_found=True)

    def create_bucket(self, name, location):
        require(self.bucket(name) is None, 'Bucket already exists; use manual credentials mode or choose a new name')
        body = {'name': name, 'storageClass': 'Standard'}
        if location != 'auto':
            body['locationHint'] = location
        result = self.request('POST', f'/accounts/{self.account}/r2/buckets', body)
        require(isinstance(result, dict) and result.get('name') == name, 'Unexpected created bucket')
        return result

    def check_private(self, name):
        managed = self.request('GET', f'/accounts/{self.account}/r2/buckets/{name}/domains/managed')
        custom = self.request('GET', f'/accounts/{self.account}/r2/buckets/{name}/domains/custom')
        require(isinstance(managed, dict) and managed.get('enabled') is False,
                'The new bucket must have public r2.dev access disabled')
        require(isinstance(custom, dict) and custom.get('domains') == [],
                'The new bucket must not have public custom domains')

    def create_object_token(self, bucket, name, groups):
        body = {'name': name, 'policies': [{'effect': 'allow', 'permission_groups': groups,
                'resources': {f'com.cloudflare.edge.r2.bucket.{self.account}_default_{bucket}': '*'}}]}
        result = self.request('POST', f'/accounts/{self.account}/tokens', body)
        require(isinstance(result, dict) and re.fullmatch('[a-fA-F0-9]{32}', result.get('id', ''))
                and isinstance(result.get('value'), str) and 40 <= len(result['value']) <= 80,
                'Token creation response is incomplete; inspect the named token before retrying')
        return {'access_key_id': result['id'],
                'secret_access_key': hashlib.sha256(result['value'].encode()).hexdigest()}

    def forget(self):
        self._token = ''
