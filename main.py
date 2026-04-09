"""Simple Litecoin Wallet RPC with ElectrumX integration."""

import asyncio
import json
import ssl
import logging
import os
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone
import hashlib

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from bip_utils import P2WPKHAddrDecoder
from contextlib import asynccontextmanager


# ============================================================================
# Configuration
# ============================================================================

env_path = os.getenv("ENV_FILE", ".env")
if Path(env_path).exists():
    load_dotenv(env_path)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-8s] %(name)s - %(message)s",
)
log = logging.getLogger(__name__)

# Environment variables
ELECTRUMX_HOST = os.getenv("ELECTRUMX_HOST", "localhost")
ELECTRUMX_PORT = int(os.getenv("ELECTRUMX_PORT", "50002"))
IS_TESTNET = os.getenv("TESTNET", "false").lower() == "true"
ADDRESS_HRP = "tltc" if IS_TESTNET else "ltc"

log.info(f"Config: ElectrumX={ELECTRUMX_HOST}:{ELECTRUMX_PORT}, Testnet={IS_TESTNET}, HRP={ADDRESS_HRP}")


# ============================================================================
# Utilities
# ============================================================================

def address_to_scripthash(address: str) -> str:
    """Convert Litecoin bech32 address to ElectrumX script hash."""
    try:
        log.debug(f"Converting address {address} to script hash")
        decoder = P2WPKHAddrDecoder()
        witness_program = decoder.DecodeAddr(address, hrp=ADDRESS_HRP)
        script_pubkey = bytes.fromhex("0014") + witness_program
        script_hash = hashlib.sha256(script_pubkey).digest()[::-1]
        result = script_hash.hex()
        log.debug(f"  -> {result}")
        return result
    except Exception as e:
        log.error(f"Failed to convert address {address}: {e}")
        raise ValueError(f"Invalid address {address}: {e}")


# ============================================================================
# Pydantic Models
# ============================================================================

class AddressListRequest(BaseModel):
    """Request with list of wallet addresses."""
    addresses: list[str]


class HistoryRequest(BaseModel):
    """Request for transaction history."""
    addresses: list[str]


class SubscribeRequest(BaseModel):
    """Request to subscribe to addresses."""
    addresses: list[str]


class UnsubscribeRequest(BaseModel):
    """Request to unsubscribe from addresses."""
    addresses: list[str]


# ============================================================================
# ElectrumX Client
# ============================================================================

class ElectrumXClient:
    """Simple ElectrumX TCP/SSL client with batch request support."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.request_id_counter = 0
        self.read_lock = asyncio.Lock()
        self.subscribed_hashes: set[str] = set()
        self.logger = logging.getLogger(f"{__name__}.ElectrumXClient")

    async def connect(self):
        """Connect to ElectrumX server."""
        self.logger.info(f"Connecting to {self.host}:{self.port}")
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        self.reader, self.writer = await asyncio.open_connection(
            self.host, self.port, ssl=context
        )
        self.logger.info(f"✓ Connected to {self.host}:{self.port}")
        
        # Handshake
        response = await self._send_request("server.version", ["wallet-rpc", "1.4"], request_id=0)
        if "error" in response:
            raise RuntimeError(f"Handshake failed: {response['error']}")
        server_info = response.get("result", [])
        self.logger.info(f"✓ Handshake OK - Server: {server_info[0] if server_info else 'Unknown'}, Protocol: {server_info[1] if len(server_info) > 1 else 'Unknown'}")

    async def disconnect(self):
        """Disconnect from server."""
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            self.logger.info("Disconnected")

    async def _send_request(self, method: str, params: Optional[list] = None, request_id: Optional[int] = None) -> dict:
        """Send JSON-RPC request and wait for response."""
        if params is None:
            params = []
        if request_id is None:
            self.request_id_counter += 1
            request_id = self.request_id_counter

        request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        raw_request = json.dumps(request).encode("utf-8") + b"\n"
        
        self.logger.debug(f">>> Sending: {method} (id={request_id})")

        async with self.read_lock:
            self.writer.write(raw_request)
            await self.writer.drain()

            # Read responses until we get matching request_id
            buffer = b""
            while True:
                if b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if line.strip():
                        try:
                            msg = json.loads(line.decode("utf-8"))
                            self.logger.debug(f"<<< Received: {json.dumps(msg)}")
                            msg_id = msg.get("id")

                            if msg_id == request_id:
                                return msg
                            elif "method" in msg and "id" not in msg:
                                # Server notification (no id field)
                                self.logger.info(f"[NOTIFICATION] {msg.get('method')}: {msg.get('params')}")
                            else:
                                self.logger.warning(f"[UNEXPECTED] {json.dumps(msg)}")
                        except json.JSONDecodeError as e:
                            self.logger.error(f"JSON decode error: {e}")

                try:
                    chunk = await asyncio.wait_for(self.reader.read(4096), timeout=30)
                except asyncio.TimeoutError:
                    raise RuntimeError("Timeout waiting for response")

                if not chunk:
                    raise ConnectionError("Server closed connection")

                buffer += chunk
                self.logger.debug(f"[BUFFER] Received {len(chunk)} bytes")

    async def get_history_batch(self, script_hashes: list[str]) -> dict[str, list[dict]]:
        """Get history for multiple script hashes in batch."""
        self.logger.info(f"Fetching history for {len(script_hashes)} script hashes")
        
        # Send all requests
        tasks = []
        for script_hash in script_hashes:
            self.request_id_counter += 1
            request_id = self.request_id_counter
            tasks.append((script_hash, request_id, self._send_request("blockchain.scripthash.get_history", [script_hash], request_id)))

        # Gather results
        results = {}
        for script_hash, request_id, task in tasks:
            try:
                response = await task
                if "error" in response:
                    self.logger.error(f"Error for {script_hash}: {response['error']}")
                    results[script_hash] = []
                else:
                    results[script_hash] = response.get("result", [])
                    self.logger.info(f"✓ Got {len(results[script_hash])} transactions for {script_hash[:16]}...")
            except Exception as e:
                self.logger.error(f"Exception for {script_hash}: {e}")
                results[script_hash] = []

        return results

    async def _batch_requests(self, requests_list: list[tuple]) -> list[dict]:
        """Send multiple requests in batch and read all responses.
        
        Args:
            requests_list: List of (method, params, request_id) tuples
            
        Returns:
            List of responses indexed by request_id
        """
        self.logger.debug(f"Batch sending {len(requests_list)} requests")
        
        # Build all requests
        raw_requests = []
        request_ids = {}
        for method, params, request_id in requests_list:
            request = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
            raw_request = json.dumps(request).encode("utf-8") + b"\n"
            raw_requests.append(raw_request)
            request_ids[request_id] = method
            self.logger.debug(f"  [{request_id}] {method}")

        # Send all at once
        async with self.read_lock:
            for raw_request in raw_requests:
                self.writer.write(raw_request)
            await self.writer.drain()
            self.logger.debug(f"✓ Sent {len(raw_requests)} requests in batch")

            # Now read all responses
            responses = {}
            buffer = b""
            expected_count = len(requests_list)
            received_count = 0

            while received_count < expected_count:
                if b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if line.strip():
                        try:
                            msg = json.loads(line.decode("utf-8"))
                            self.logger.debug(f"<<< Received: {json.dumps(msg)}")
                            msg_id = msg.get("id")
                            self.logger.debug(f"    msg_id={msg_id}, in request_ids={msg_id in request_ids}, request_ids keys={list(request_ids.keys())}")

                            if msg_id in request_ids:
                                responses[msg_id] = msg
                                received_count += 1
                                self.logger.debug(f"    ✓ Counted! Now {received_count}/{expected_count}")
                                
                                # Check if we have all responses - break immediately
                                if received_count >= expected_count:
                                    self.logger.debug(f"✓ Got all {expected_count} responses, exiting read loop")
                                    break
                                    
                            elif "method" in msg and "id" not in msg:
                                # Server notification
                                self.logger.info(f"[NOTIFICATION] {msg.get('method')}: {msg.get('params')}")
                            else:
                                self.logger.warning(f"[UNEXPECTED] {json.dumps(msg)}")
                        except json.JSONDecodeError as e:
                            self.logger.error(f"JSON decode error: {e}")

                # Only try to read more if we still need responses
                if received_count >= expected_count:
                    break
                    
                try:
                    chunk = await asyncio.wait_for(self.reader.read(4096), timeout=30)
                except asyncio.TimeoutError:
                    self.logger.error(f"Timeout: got {received_count}/{expected_count} responses")
                    raise RuntimeError(f"Timeout waiting for batch responses (got {received_count}/{expected_count})")

                if not chunk:
                    if received_count >= expected_count:
                        break
                    self.logger.error(f"Connection closed: got {received_count}/{expected_count} responses")
                    raise ConnectionError(f"Server closed connection after {received_count}/{expected_count} responses")

                buffer += chunk
                self.logger.debug(f"[BUFFER] Received {len(chunk)} bytes, have {received_count}/{expected_count} responses")

        return [responses.get(req[2]) for req in requests_list]

    async def subscribe(self, script_hashes: list[str]):
        """Subscribe to script hashes in batch."""
        self.logger.info(f"Subscribing to {len(script_hashes)} script hashes")
        
        # Prepare batch requests
        batch = []
        for script_hash in script_hashes:
            self.request_id_counter += 1
            batch.append(("blockchain.scripthash.subscribe", [script_hash], self.request_id_counter))
        
        # Send batch
        responses = await self._batch_requests(batch)
        
        # Process responses
        for (method, params, req_id), response in zip(batch, responses):
            script_hash = params[0]
            if response is None:
                self.logger.error(f"No response for {script_hash[:16]}...")
            elif "error" in response:
                self.logger.error(f"Subscription failed for {script_hash[:16]}...: {response['error']}")
            else:
                status_hash = response.get("result")
                self.subscribed_hashes.add(script_hash)
                self.logger.info(f"✓ Subscribed to {script_hash[:16]}... (status: {status_hash[:16] if status_hash else 'None'}...)")

    async def unsubscribe(self, script_hashes: list[str]):
        """Unsubscribe from script hashes in batch."""
        self.logger.info(f"Unsubscribing from {len(script_hashes)} script hashes")
        
        # Prepare batch requests
        batch = []
        for script_hash in script_hashes:
            self.request_id_counter += 1
            batch.append(("blockchain.scripthash.unsubscribe", [script_hash], self.request_id_counter))
        
        # Send batch
        responses = await self._batch_requests(batch)
        
        # Process responses
        for (method, params, req_id), response in zip(batch, responses):
            script_hash = params[0]
            # Always remove from local tracking
            self.subscribed_hashes.discard(script_hash)
            
            if response is None:
                self.logger.error(f"No response for {script_hash[:16]}...")
            elif "error" in response:
                error = response['error']
                if error.get('code') == -32601:
                    self.logger.warning(f"Server doesn't support unsubscribe (needs v1.4.2+), removed locally: {script_hash[:16]}...")
                else:
                    self.logger.warning(f"Unsubscribe error for {script_hash[:16]}...: {error}")
            else:
                result = response.get("result")
                self.logger.info(f"✓ Unsubscribed from {script_hash[:16]}... (was_subscribed: {result})")

    async def ping(self):
        """Send keepalive ping."""
        try:
            response = await self._send_request("server.ping", [])
            if "error" not in response:
                self.logger.debug("Ping successful")
        except Exception as e:
            self.logger.error(f"Ping failed: {e}")


# ============================================================================
# Background Tasks
# ============================================================================

async def keepalive_task(client: ElectrumXClient):
    """Send ping every 5 minutes to keep connection alive."""
    while True:
        try:
            await asyncio.sleep(300)  # 5 minutes
            await client.ping()
        except asyncio.CancelledError:
            log.info("Keepalive task cancelled")
            break
        except Exception as e:
            log.error(f"Keepalive error: {e}")


# ============================================================================
# Global State
# ============================================================================

electrum_client: Optional[ElectrumXClient] = None


# ============================================================================
# FastAPI Lifespan
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown."""
    global electrum_client
    
    log.info("Starting Litecoin Wallet RPC")
    
    # Connect to ElectrumX
    electrum_client = ElectrumXClient(ELECTRUMX_HOST, ELECTRUMX_PORT)
    try:
        await electrum_client.connect()
        
        # Start keepalive task
        keepalive = asyncio.create_task(keepalive_task(electrum_client))
        
        yield
        
        # Shutdown
        keepalive.cancel()
        try:
            await keepalive
        except asyncio.CancelledError:
            pass
        
        await electrum_client.disconnect()
    except Exception as e:
        log.error(f"Failed to connect to ElectrumX: {e}")
        raise


# ============================================================================
# FastAPI App
# ============================================================================

app = FastAPI(title="Litecoin Wallet RPC", lifespan=lifespan)


# ============================================================================
# API Endpoints
# ============================================================================

@app.get("/health")
async def health():
    """Health check."""
    return {
        "status": "healthy" if electrum_client else "unhealthy",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/history")
async def get_history(request: HistoryRequest):
    """Get transaction history for addresses."""
    if not electrum_client:
        raise HTTPException(status_code=503, detail="ElectrumX not connected")
    
    log.info(f"History request for {len(request.addresses)} addresses")
    
    # Convert addresses to script hashes
    script_hashes = []
    addr_to_hash = {}
    for addr in request.addresses:
        try:
            script_hash = address_to_scripthash(addr)
            script_hashes.append(script_hash)
            addr_to_hash[script_hash] = addr
        except ValueError as e:
            log.error(f"Invalid address {addr}: {e}")
            raise HTTPException(status_code=400, detail=str(e))
    
    # Get history
    results = await electrum_client.get_history_batch(script_hashes)
    
    # Format response
    response = {}
    for script_hash, history in results.items():
        address = addr_to_hash.get(script_hash, script_hash)
        response[address] = {
            "transactions": history,
            "count": len(history),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    return response


@app.post("/subscribe")
async def subscribe(request: SubscribeRequest):
    """Subscribe to address updates."""
    if not electrum_client:
        raise HTTPException(status_code=503, detail="ElectrumX not connected")
    
    log.info(f"Subscribe request for {len(request.addresses)} addresses")
    
    # Convert addresses to script hashes
    script_hashes = []
    addr_to_hash = {}
    for addr in request.addresses:
        try:
            script_hash = address_to_scripthash(addr)
            script_hashes.append(script_hash)
            addr_to_hash[script_hash] = addr
        except ValueError as e:
            log.error(f"Invalid address {addr}: {e}")
            raise HTTPException(status_code=400, detail=str(e))
    
    # Subscribe
    await electrum_client.subscribe(script_hashes)
    
    return {
        "status": "subscribed",
        "addresses": request.addresses,
        "count": len(request.addresses),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/unsubscribe")
async def unsubscribe(request: UnsubscribeRequest):
    """Unsubscribe from address updates."""
    if not electrum_client:
        raise HTTPException(status_code=503, detail="ElectrumX not connected")
    
    log.info(f"Unsubscribe request for {len(request.addresses)} addresses")
    
    # Convert addresses to script hashes
    script_hashes = []
    for addr in request.addresses:
        try:
            script_hash = address_to_scripthash(addr)
            script_hashes.append(script_hash)
        except ValueError as e:
            log.error(f"Invalid address {addr}: {e}")
            raise HTTPException(status_code=400, detail=str(e))
    
    # Unsubscribe
    await electrum_client.unsubscribe(script_hashes)
    
    return {
        "status": "unsubscribed",
        "addresses": request.addresses,
        "count": len(request.addresses),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.get("/subscriptions")
async def list_subscriptions():
    """List active subscriptions."""
    if not electrum_client:
        raise HTTPException(status_code=503, detail="ElectrumX not connected")
    
    return {
        "subscribed": list(electrum_client.subscribed_hashes),
        "count": len(electrum_client.subscribed_hashes),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
