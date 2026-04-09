import asyncio
import json
import ssl
import logging
import os
from pathlib import Path
from typing import Optional
import datetime as dt
from datetime import datetime
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from bip_utils import Bip39MnemonicGenerator, Bip39WordsNum, P2WPKHAddrDecoder
import hashlib

# Load environment variables from .env file
env_path = os.getenv("ENV_FILE", ".env")
if Path(env_path).exists():
    load_dotenv(env_path)
    env_source = f"from {env_path}"
else:
    env_source = "from system environment"

# Configure logging to use a proper logger instead of uvicorn.error
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s - %(message)s",
)
log = logging.getLogger(__name__)
log.info(f"Loaded environment {env_source}")

# Suppress overly verbose uvicorn logging
# logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
# logging.getLogger("uvicorn.error").setLevel(logging.WARNING)


# ============================================================================
# Address Conversion Utilities
# ============================================================================


def get_address_hrp() -> str:
    """Get the HRP (Human Readable Part) for addresses based on testnet flag."""
    is_testnet = os.getenv("TESTNET", "false").lower() == "true"
    return "tltc" if is_testnet else "ltc"


def address_to_scripthash(address: str) -> str:
    """
    Convert a Litecoin/Litecoin-testnet bech32 address (P2WPKH) to ElectrumX-compatible script hash.

    Args:
        address: Litecoin bech32 address (starting with ltc1 or tltc1)

    Returns:
        Script hash as hex string in little-endian format (ElectrumX format)
    """
    try:
        # Decode the bech32 address to get the witness program
        decoder = P2WPKHAddrDecoder()
        hrp = get_address_hrp()
        witness_program = decoder.DecodeAddr(address, hrp=hrp)

        # For P2WPKH, ScriptPubKey is 0x0014 + 20-byte witness program
        script_pubkey = bytes.fromhex("0014") + witness_program

        # Compute SHA256 hash of the scriptPubKey
        script_hash = hashlib.sha256(script_pubkey).digest()

        # Convert to little-endian (reverse byte order) for ElectrumX
        script_hash_le = script_hash[::-1]

        return script_hash_le.hex()
    except Exception as e:
        raise ValueError(f"Failed to convert address to script hash: {e}")


# ============================================================================
# Pydantic Models
# ============================================================================


class AddressRequest(BaseModel):
    """Request with wallet addresses instead of script hashes."""

    addresses: list[str]


class ScriptHashRequest(BaseModel):
    """Request with script hashes."""

    script_hashes: list[str]


class BalanceRequest(BaseModel):
    """Request for balance (supports both addresses and script hashes)."""

    script_hashes: Optional[list[str]] = None
    addresses: Optional[list[str]] = None

    def get_script_hashes(self) -> list[str]:
        """Get script hashes, converting addresses if needed."""
        if self.script_hashes:
            return self.script_hashes
        elif self.addresses:
            return [address_to_scripthash(addr) for addr in self.addresses]
        else:
            raise ValueError("Either script_hashes or addresses must be provided")


class SubscribeRequest(BaseModel):
    """Subscribe request."""

    script_hashes: Optional[list[str]] = None
    addresses: Optional[list[str]] = None
    webhook_url: Optional[str] = None

    def get_script_hashes(self) -> list[str]:
        """Get script hashes, converting addresses if needed."""
        if self.script_hashes:
            return self.script_hashes
        elif self.addresses:
            return [address_to_scripthash(addr) for addr in self.addresses]
        else:
            raise ValueError("Either script_hashes or addresses must be provided")


class BalanceResponse(BaseModel):
    script_hash: str
    address: Optional[str] = None
    confirmed: int
    unconfirmed: int
    confirmed_ltc: float
    unconfirmed_ltc: float
    timestamp: str


class TransactionResponse(BaseModel):
    script_hash: str
    address: Optional[str] = None
    tx_hash: str
    height: int
    fee: Optional[int] = None
    timestamp: str


# ============================================================================
# ElectrumX Client
# ============================================================================


class ElectrumXClient:
    """Persistent TCP/SSL connection to ElectrumX server with request queueing."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.request_id_counter = 0
        self.logger = logging.getLogger(f"{__name__}.ElectrumXClient")

    async def connect(self):
        """Establish SSL connection to ElectrumX server."""
        try:
            self.logger.info(f"Connecting to ElectrumX at {self.host}:{self.port}")

            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect with asyncio
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port, ssl=context
            )

            self.logger.info(f"Connected to {self.host}:{self.port}")

            # Perform handshake
            await self._handshake()

        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            raise

    async def disconnect(self):
        """Close connection."""
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            self.logger.info("Disconnected from ElectrumX")

    async def _handshake(self):
        """Send server.version handshake."""
        response = await self._send_request(
            "server.version", ["litecoin-wallet-rpc", "1.4"], request_id=0
        )

        if "error" in response:
            raise RuntimeError(f"Handshake failed: {response['error']}")

        server_info = response["result"]
        self.logger.info(
            f"Handshake OK - Server: {server_info[0]}, Protocol: {server_info[1]}"
        )

    async def _send_request(
        self,
        method: str,
        params: Optional[list] = None,
        request_id: Optional[int] = None,
    ):
        """Send JSON-RPC request and wait for matching response."""
        if params is None:
            params = []

        if request_id is None:
            self.request_id_counter += 1
            request_id = self.request_id_counter

        request = {"id": request_id, "method": method, "params": params}

        raw_request = json.dumps(request).encode("utf-8") + b"\n"

        self.logger.debug(f">>> Sending {method} (id={request_id})")
        self.writer.write(raw_request)
        await self.writer.drain()

        # Read responses until we get one matching our request_id
        buffer = b""
        while True:
            if b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                if line.strip():
                    try:
                        msg = json.loads(line.decode("utf-8"))
                        msg_id = msg.get("id")

                        if msg_id == request_id:
                            self.logger.debug(
                                f"<<< Received response (id={request_id})"
                            )
                            return msg
                        elif "method" in msg:
                            # Server notification
                            self.logger.info(
                                f"[Notification] {msg.get('method')} - {msg.get('params')}"
                            )
                        else:
                            self.logger.warning(f"[Unexpected] {json.dumps(msg)}")
                    except json.JSONDecodeError as e:
                        self.logger.error(f"Failed to parse JSON: {e}")

            try:
                chunk = await asyncio.wait_for(self.reader.read(4096), timeout=30)
            except asyncio.TimeoutError:
                raise RuntimeError("Timeout waiting for response")

            if not chunk:
                raise ConnectionError("Server closed the connection")

            buffer += chunk

    async def get_balance(self, script_hash: str) -> dict:
        """Get balance for a script hash."""
        response = await self._send_request(
            "blockchain.scripthash.get_balance", [script_hash]
        )

        if "error" in response:
            raise RuntimeError(f"Balance query failed: {response['error']}")

        result = response["result"]
        confirmed = result.get("confirmed", 0)
        unconfirmed = result.get("unconfirmed", 0)

        return {
            "script_hash": script_hash,
            "confirmed": confirmed,
            "unconfirmed": unconfirmed,
            "confirmed_ltc": confirmed / 1e8,
            "unconfirmed_ltc": unconfirmed / 1e8,
            "timestamp": datetime.now(dt.timezone.utc).isoformat(),
        }

    async def get_history(self, script_hash: str) -> list[dict]:
        """Get transaction history for a script hash."""
        response = await self._send_request(
            "blockchain.scripthash.get_history", [script_hash]
        )

        if "error" in response:
            raise RuntimeError(f"History query failed: {response['error']}")

        history = response["result"]
        return [
            {
                "script_hash": script_hash,
                "tx_hash": tx["tx_hash"],
                "height": tx.get("height", -1),
                "fee": tx.get("fee"),
                "timestamp": datetime.now(dt.timezone.utc).isoformat(),
            }
            for tx in history
        ]


# ============================================================================
# Subscription Manager
# ============================================================================


class SubscriptionManager:
    """Manages script hash subscriptions and results."""

    def __init__(self):
        self._subscribed_hashes: dict[
            str, dict
        ] = {}  # {script_hash: {webhook_url, ...}}
        self._hash_results: dict[str, dict] = {}  # {script_hash: balance_data}
        self._lock = asyncio.Lock()
        self.logger = logging.getLogger(f"{__name__}.SubscriptionManager")

    async def subscribe(self, script_hash: str, webhook_url: Optional[str] = None):
        """Subscribe to updates for a script hash."""
        async with self._lock:
            if script_hash not in self._subscribed_hashes:
                self._subscribed_hashes[script_hash] = {}
                self.logger.info(f"New subscription: {script_hash}")

            if webhook_url:
                self._subscribed_hashes[script_hash]["webhook_url"] = webhook_url
                # self.logger.info(f"  - Webhook: {webhook_url}")

    async def unsubscribe(self, script_hash: str) -> bool:
        """Unsubscribe from updates for a script hash. Returns True if was subscribed."""
        async with self._lock:
            if script_hash in self._subscribed_hashes:
                del self._subscribed_hashes[script_hash]
                self.logger.info(f"Unsubscribed from: {script_hash}")
                return True
            return False

    async def store_result(self, script_hash: str, result: dict):
        """Store balance result for a script hash."""
        async with self._lock:
            self._hash_results[script_hash] = result
            self.logger.info(
                f"Updated balance for {script_hash}: "
                f"{result['confirmed_ltc']:.8f} LTC confirmed, "
                f"{result['unconfirmed_ltc']:.8f} LTC unconfirmed"
            )

    async def get_result(self, script_hash: str) -> Optional[dict]:
        """Get stored result for a script hash."""
        async with self._lock:
            return self._hash_results.get(script_hash)

    async def get_all_subscribed(self) -> dict[str, dict]:
        """Get all subscribed hashes."""
        async with self._lock:
            return self._subscribed_hashes.copy()

    async def get_all_results(self) -> dict[str, dict]:
        """Get all results."""
        async with self._lock:
            return self._hash_results.copy()

    async def on_update(self, script_hash: str, result: dict):
        """Called when a subscription receives an update. For now, just logs."""
        await self.store_result(script_hash, result)

        # In production, this would:
        # - Call webhook_url if registered
        # - Send to WebSocket clients
        # - etc.

        self.logger.info(f"[Webhook] Would notify subscribers of {script_hash} update")


# ============================================================================
# FastAPI Application
# ============================================================================

# Global state
electrum_client: Optional[ElectrumXClient] = None
subscription_manager: Optional[SubscriptionManager] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown."""
    global electrum_client, subscription_manager

    # Startup
    log.info("Starting Litecoin Wallet RPC Microservice")
    subscription_manager = SubscriptionManager()

    # ElectrumX connection is optional, can be disabled for testing
    enable_electrumx = os.getenv("ENABLE_ELECTRUMX", "true").lower() == "true"

    if enable_electrumx:
        electrum_host = os.getenv("ELECTRUMX_HOST")
        electrum_port = int(os.getenv("ELECTRUMX_PORT"))

        electrum_client = ElectrumXClient(host=electrum_host, port=electrum_port)

        try:
            await electrum_client.connect()
        except Exception as e:
            log.error(f"Failed to connect to ElectrumX: {e}")
            log.warning("Continuing without ElectrumX connection")
            electrum_client = None
    else:
        log.info("ElectrumX disabled (ENABLE_ELECTRUMX=false)")
        electrum_client = None

    yield

    # Shutdown
    log.info("Shutting down")
    if electrum_client:
        await electrum_client.disconnect()


app = FastAPI(
    title="Litecoin Wallet RPC",
    description="ElectrumX-based RPC for Litecoin wallet operations",
    lifespan=lifespan,
)


# ============================================================================
# API Endpoints
# ============================================================================


@app.get("/seed")
async def generate_seed():
    """Generate a new 24-word BIP39 mnemonic."""
    mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)
    return {"mnemonic": mnemonic.ToStr()}


@app.post("/balance", response_model=list[BalanceResponse])
async def get_balances(request: BalanceRequest):
    """Get balances for addresses or script hashes (batch operation, list-first)."""
    if not electrum_client:
        raise HTTPException(status_code=503, detail="ElectrumX not connected")

    try:
        script_hashes = request.get_script_hashes()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    results = []
    for script_hash in script_hashes:
        try:
            result = await electrum_client.get_balance(script_hash)
            await subscription_manager.store_result(script_hash, result)
            results.append(result)
        except Exception as e:
            log.error(f"Error querying {script_hash}: {e}")
            results.append(
                {
                    "script_hash": script_hash,
                    "confirmed": 0,
                    "unconfirmed": 0,
                    "confirmed_ltc": 0.0,
                    "unconfirmed_ltc": 0.0,
                    "timestamp": datetime.now(dt.timezone.utc).isoformat(),
                    "error": str(e),
                }
            )

    return results


@app.post("/history", response_model=list[TransactionResponse])
async def get_history_batch(request: BalanceRequest):
    """Get transaction history for addresses or script hashes (batch operation, list-first)."""
    if not electrum_client:
        raise HTTPException(status_code=503, detail="ElectrumX not connected")

    try:
        script_hashes = request.get_script_hashes()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    all_results = []
    for script_hash in script_hashes:
        try:
            results = await electrum_client.get_history(script_hash)
            all_results.extend(results)
        except Exception as e:
            log.error(f"Error querying history for {script_hash}: {e}")

    return all_results


@app.post("/subscribe")
async def subscribe(request: SubscribeRequest):
    """Subscribe to updates for addresses or script hashes."""
    if not subscription_manager:
        raise HTTPException(status_code=503, detail="Service not ready")

    try:
        script_hashes = request.get_script_hashes()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    subscribed = []
    for script_hash in script_hashes:
        await subscription_manager.subscribe(script_hash, request.webhook_url)
        subscribed.append(script_hash)

    return {
        "status": "subscribed",
        "script_hashes": subscribed,
        "webhook_url": request.webhook_url,
        "message": "In production, updates would be sent to the webhook URL",
    }


@app.delete("/subscribe")
async def unsubscribe_batch(request: BalanceRequest):
    """Unsubscribe from updates for addresses or script hashes (batch operation)."""
    if not subscription_manager:
        raise HTTPException(status_code=503, detail="Service not ready")

    try:
        script_hashes = request.get_script_hashes()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    unsubscribed = []
    for script_hash in script_hashes:
        was_subscribed = await subscription_manager.unsubscribe(script_hash)
        unsubscribed.append(
            {"script_hash": script_hash, "was_subscribed": was_subscribed}
        )

    return {
        "status": "unsubscribed",
        "script_hashes": [item["script_hash"] for item in unsubscribed],
        "details": unsubscribed,
    }


@app.get("/subscriptions")
async def list_subscriptions():
    """List all active subscriptions."""
    if not subscription_manager:
        raise HTTPException(status_code=503, detail="Service not ready")

    subscribed = await subscription_manager.get_all_subscribed()
    results = await subscription_manager.get_all_results()

    return {
        "total_subscriptions": len(subscribed),
        "subscribed_hashes": list(subscribed.keys()),
        "results": results,
    }


@app.get("/health")
async def health():
    """Health check."""
    return {
        "status": "healthy",
        "electrum_connected": electrum_client is not None
        and electrum_client.reader is not None,
        "timestamp": datetime.now(dt.timezone.utc).isoformat(),
    }
