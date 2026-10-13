import re
import uuid


_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


class RequestIdService:
    def resolve(self, inbound):
        if isinstance(inbound, str) and _SAFE_REQUEST_ID.fullmatch(inbound):
            return inbound
        return str(uuid.uuid4())
