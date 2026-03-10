#!/usr/bin/env python3
"""
MeshCore packet decoder bridge for MC-Keygen 2.0.
Called by the Node.js server to decode and decrypt packets.

Usage:
  python3 decoder.py decode <hex_packet>
  python3 decoder.py decrypt <hex_packet> <channel_key_hex>
  python3 decoder.py extract-hash <hex_packet>

Output is JSON to stdout.
"""
import sys
import json
import hashlib

try:
    from meshcoredecoder import MeshCorePacketDecoder
    from meshcoredecoder.types.crypto import DecryptionOptions
    DECODER_AVAILABLE = True
except ImportError:
    DECODER_AVAILABLE = False


def decode_packet(hex_data, channel_key=None):
    """Decode a packet, optionally trying to decrypt with a channel key."""
    if not DECODER_AVAILABLE:
        return {"error": "meshcoredecoder not installed"}

    decoder = MeshCorePacketDecoder()
    options = None

    if channel_key:
        ks = decoder.create_key_store()
        ks.add_channel_secrets([channel_key.strip()])
        options = DecryptionOptions(key_store=ks, attempt_decryption=True)

    try:
        result = decoder.decode_to_json(hex_data.strip(), options=options)
        return json.loads(result)
    except Exception as exc:
        return {"error": str(exc)}


def extract_channel_hash(hex_data):
    """Decode a packet and extract the channelHash field if present."""
    if not DECODER_AVAILABLE:
        return {"error": "meshcoredecoder not installed"}

    decoder = MeshCorePacketDecoder()
    try:
        result = decoder.decode_to_json(hex_data.strip())
        parsed = json.loads(result)

        # Look for channelHash in decoded payload
        payload = parsed.get("payload", {})
        decoded = payload.get("decoded", {})
        channel_hash = decoded.get("channelHash")

        return {
            "channelHash": channel_hash,
            "payloadType": parsed.get("payloadType"),
            "isValid": parsed.get("isValid"),
            "decoded": parsed,
        }
    except Exception as exc:
        return {"error": str(exc)}


def try_decrypt(hex_data, channel_key):
    """Try to decrypt a packet with a specific channel key. Returns decoded JSON."""
    if not DECODER_AVAILABLE:
        return {"error": "meshcoredecoder not installed", "success": False}

    decoder = MeshCorePacketDecoder()
    ks = decoder.create_key_store()
    ks.add_channel_secrets([channel_key.strip()])
    options = DecryptionOptions(key_store=ks, attempt_decryption=True)

    try:
        result = decoder.decode_to_json(hex_data.strip(), options=options)
        parsed = json.loads(result)

        # Check if decryption succeeded by looking for decrypted payload content
        payload = parsed.get("payload", {})
        decoded = payload.get("decoded", {})
        decrypted = decoded.get("decrypted") or decoded.get("message")

        return {
            "success": decrypted is not None,
            "decoded": parsed,
            "channelKey": channel_key,
        }
    except Exception as exc:
        return {"error": str(exc), "success": False}


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(json.dumps({"error": "Usage: decoder.py <command> <args...>"}))
        sys.exit(1)

    command = sys.argv[1]

    if command == "decode":
        hex_data = sys.argv[2]
        result = decode_packet(hex_data)
        print(json.dumps(result))

    elif command == "decrypt":
        if len(sys.argv) < 4:
            print(json.dumps({"error": "Usage: decoder.py decrypt <hex> <key>"}))
            sys.exit(1)
        hex_data = sys.argv[2]
        channel_key = sys.argv[3]
        result = try_decrypt(hex_data, channel_key)
        print(json.dumps(result))

    elif command == "extract-hash":
        hex_data = sys.argv[2]
        result = extract_channel_hash(hex_data)
        print(json.dumps(result))

    elif command == "check":
        # Health check
        print(json.dumps({
            "available": DECODER_AVAILABLE,
            "version": "1.0",
        }))

    else:
        print(json.dumps({"error": f"Unknown command: {command}"}))
        sys.exit(1)
