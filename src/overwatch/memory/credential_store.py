"""
CredentialStore - encrypted credential management using Fernet symmetric encryption.

All credential values are encrypted at rest using the Fernet key. The key should
be stored securely (e.g., environment variable, HashiCorp Vault) and never
committed to source control.
"""
import base64
import logging
from datetime import datetime
from typing import Any, List, Optional

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import Credential

logger = logging.getLogger(__name__)


class CredentialStore:
    """
    Encrypted credential management backed by the database Credential table.

    Encryption uses Fernet (AES-128-CBC + HMAC-SHA256) from the cryptography
    library. A new Fernet key is generated if none is provided — callers should
    persist and reuse the same key across restarts, otherwise old credentials
    become unreadable.
    """

    def __init__(
        self,
        session_factory: Any,
        fernet_key: Optional[bytes] = None,
    ) -> None:
        if fernet_key is None:
            fernet_key = Fernet.generate_key()
            logger.warning(
                "CredentialStore: no Fernet key provided — generated a new ephemeral "
                "key. Credentials stored in this session cannot be decrypted after "
                "restart. Set FERNET_KEY env var for persistence."
            )
        self._fernet = Fernet(fernet_key)
        self._session_factory = session_factory

    # ─────────────────────── Encryption ──────────────────────────

    def encrypt(self, value: str) -> str:
        """
        Encrypt a plaintext string and return a base64 Fernet token.

        The returned string is safe to store in the database.
        """
        token: bytes = self._fernet.encrypt(value.encode("utf-8"))
        return base64.b64encode(token).decode("ascii")

    def decrypt(self, encrypted_value: str) -> str:
        """
        Decrypt a Fernet token produced by encrypt().

        Raises cryptography.fernet.InvalidToken if the token is invalid or was
        encrypted with a different key.
        """
        token = base64.b64decode(encrypted_value.encode("ascii"))
        plaintext: bytes = self._fernet.decrypt(token)
        return plaintext.decode("utf-8")

    # ─────────────────────── Storage API ─────────────────────────

    async def store_credential(
        self,
        engagement_id: int,
        service: str,
        username: str,
        cred_type: str,
        plaintext_value: str,
        scope: str = "engagement",
    ) -> int:
        """
        Encrypt and persist a credential.

        Returns the database ID of the newly created Credential row.
        """
        encrypted = self.encrypt(plaintext_value)
        async with self._session_factory() as session:
            credential = Credential(
                engagement_id=engagement_id,
                credential_type=cred_type,
                username=username,
                service=service,
                scope=scope,
                encrypted_value=encrypted,
                discovered_at=datetime.utcnow(),
                is_valid=True,
            )
            session.add(credential)
            await session.flush()  # populate the id before commit
            credential_id: int = credential.id
            await session.commit()

        logger.info(
            "CredentialStore: stored credential id=%d service='%s' user='%s' type='%s'",
            credential_id,
            service,
            username,
            cred_type,
        )
        return credential_id

    async def get_credential(self, credential_id: int) -> Optional[dict]:
        """
        Retrieve and decrypt a single credential by ID.

        Returns None if the credential does not exist or has been invalidated.
        Returns a dict with decrypted 'plaintext_value' included.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(Credential).where(Credential.id == credential_id)
            )
            row = result.scalar_one_or_none()
            if row is None or not row.is_valid:
                return None

            try:
                plaintext = self.decrypt(row.encrypted_value)
            except InvalidToken:
                logger.error(
                    "CredentialStore: failed to decrypt credential id=%d — "
                    "key mismatch or corrupted data.",
                    credential_id,
                )
                return None

            return self._credential_to_dict(row, plaintext)

    async def get_credentials_for_service(
        self, engagement_id: int, service: str
    ) -> List[dict]:
        """
        Retrieve and decrypt all valid credentials for a given service.

        Returns a list of dicts with decrypted 'plaintext_value' included.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(Credential).where(
                    Credential.engagement_id == engagement_id,
                    Credential.service == service,
                    Credential.is_valid == True,  # noqa: E712
                )
            )
            rows = result.scalars().all()

        credentials: List[dict] = []
        for row in rows:
            try:
                plaintext = self.decrypt(row.encrypted_value)
                credentials.append(self._credential_to_dict(row, plaintext))
            except InvalidToken:
                logger.error(
                    "CredentialStore: failed to decrypt credential id=%d for "
                    "service='%s' — skipping.",
                    row.id,
                    service,
                )
        return credentials

    async def invalidate_credential(self, credential_id: int) -> None:
        """
        Mark a credential as invalid (soft delete).

        The encrypted value is retained for audit purposes; it will no longer
        be returned by get_credential or get_credentials_for_service.
        """
        async with self._session_factory() as session:
            await session.execute(
                update(Credential)
                .where(Credential.id == credential_id)
                .values(is_valid=False)
            )
            await session.commit()
        logger.info(
            "CredentialStore: invalidated credential id=%d", credential_id
        )

    # ─────────────────────── Helpers ─────────────────────────────

    @staticmethod
    def _credential_to_dict(row: Credential, plaintext: str) -> dict:
        return {
            "id": row.id,
            "engagement_id": row.engagement_id,
            "service": row.service,
            "username": row.username,
            "credential_type": row.credential_type,
            "scope": row.scope,
            "plaintext_value": plaintext,
            "discovered_at": row.discovered_at.isoformat()
            if row.discovered_at
            else None,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "is_valid": row.is_valid,
        }

    @classmethod
    def generate_key(cls) -> bytes:
        """Generate a new Fernet key suitable for use with this class."""
        return Fernet.generate_key()
