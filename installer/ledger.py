"""Nonsecret, durable intent/completion journal. Only this install owns its files."""
import json
import uuid

from .common import read_private, require, write_json
from .model import Plan


class Ledger:
    def __init__(self, path, data):
        self.path, self.data = path, data

    @classmethod
    def create(cls, path, plan):
        plan.validate()
        data = {'schema': 1, 'plan': plan.json(), 'install_id': uuid.uuid4().hex,
                'luks_uuid': str(uuid.uuid4()), 'filesystem_uuid': str(uuid.uuid4()),
                'key_id': uuid.uuid4().hex}
        write_json(path, data)
        return cls(path, data)

    @classmethod
    def load(cls, path):
        data = json.loads(read_private(path))
        require(data.get('schema') == 1, 'Unsupported setup journal version')
        Plan(**data['plan']).validate()
        for key in ('luks_uuid', 'filesystem_uuid', 'install_id', 'key_id'):
            uuid.UUID(data[key])
        return cls(path, data)

    @property
    def plan(self):
        return Plan(**self.data['plan']).validate()

    def get(self, key, default=None):
        return self.data.get(key, default)

    def set(self, **values):
        # Call only with nonsecret identity, intents, and completion flags.
        updated = {**self.data, **values}
        write_json(self.path, updated, replace=True)
        self.data = updated
