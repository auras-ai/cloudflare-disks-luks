"""Keep one set of crypt keys across retries; never retry an ambiguous token POST."""
import json
import re
import secrets

from .cloudflare import Cloudflare
from .common import confirm, hidden, read_private, require, write_json


def validate_material(material, *, complete=False):
    for name in ('crypt_password', 'crypt_salt'):
        require(isinstance(material.get(name), str) and 16 <= len(material[name].encode()) <= 1024,
                'Invalid saved encryption material; restore its backup')
    password = material.get('smb_password', '')
    require(12 <= len(password.encode()) <= 128 and password == password.strip()
            and not any(ord(c) < 32 or ord(c) == 127 for c in password),
            'Invalid SMB password')
    if complete or 'access_key_id' in material:
        require(bool(re.fullmatch('[a-fA-F0-9]{32}', material.get('access_key_id', '')))
                and bool(re.fullmatch('[a-fA-F0-9]{64}', material.get('secret_access_key', ''))),
                'R2 S3 access key/secret must be 32/64 hex characters')
    return material


def obtain(paths, ledger, *, import_r2=False, factory=Cloudflare):
    path = paths.recovery / 'material.json'
    if path.exists():
        material = validate_material(json.loads(read_private(path)))
    else:
        require(not ledger.get('keys_saved'), 'Saved keys are missing; restore them instead of generating new keys')
        material = {'crypt_password': secrets.token_urlsafe(48), 'crypt_salt': secrets.token_urlsafe(48),
                    'smb_password': hidden('New SMB password for r2disk', minimum=12, maximum=128, confirm=True)}
        validate_material(material)
        write_json(path, material)
    ledger.set(keys_saved=True)
    if 'access_key_id' in material:
        return validate_material(material, complete=True)

    def save(credentials):
        candidate = validate_material({**material, **credentials}, complete=True)
        write_json(path, candidate, replace=True)
        ledger.set(credentials_saved=True)
        return candidate

    plan = ledger.plan
    if plan.cloud_mode == 'manual' or import_r2:
        if ledger.get('token_requested'):
            confirm('Revoke the ambiguous token named ' + ledger.get('token_name')
                    + ' in Cloudflare, then create a fresh bucket-scoped credential. Confirm revocation.')
        confirm(f'Confirm {plan.bucket} is private, has no mutating lifecycle rules, and the chosen prefix is dedicated to this gateway.')
        return save({'access_key_id': hidden('R2 S3 Access Key ID'),
                     'secret_access_key': hidden('R2 S3 Secret Access Key')})

    require(not ledger.get('token_requested'),
            'Previous token creation may have succeeded. Revoke the named token in Cloudflare, then resume --import-r2; no duplicate token will be created')
    api = factory(plan.account_id, hidden('Cloudflare bootstrap API token'))
    try:
        groups = api.permission_groups()
        if not ledger.get('bucket_created'):
            if ledger.get('bucket_requested') and api.bucket(plan.bucket) is not None:
                confirm('A bucket exists after an interrupted create. Check in Cloudflare that it belongs to this setup.', plan.bucket)
            else:
                require(api.bucket(plan.bucket) is None, 'Bucket already exists; choose a new bucket or start in manual mode')
                ledger.set(bucket_requested=True)
                api.create_bucket(plan.bucket, plan.location)
            ledger.set(bucket_created=True)
        api.check_private(plan.bucket)
        name = 'cloudflare-disk-' + ledger.get('install_id')
        ledger.set(token_requested=True, token_name=name)
        # One-time value is converted to S3 credentials inside the API module.
        return save(api.create_object_token(plan.bucket, name, groups))
    finally:
        api.forget()
