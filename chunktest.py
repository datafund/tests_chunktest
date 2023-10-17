#!/bin/python3
import os
import random
import argparse
import json
import requests
import hashlib
from Crypto.Hash import keccak


MAX_CHUNK_PAYLOAD_SIZE = 4096
SEGMENT_SIZE = 32
SEGMENT_PAIR_SIZE = 2 * SEGMENT_SIZE
HASH_SIZE = 32

def serialize_bytes(*arrays):
    length = sum(len(arr) for arr in arrays)
    buffer = bytearray(length)
    offset = 0
    for arr in arrays:
        buffer[offset:offset + len(arr)] = arr
        offset += len(arr)
    return buffer

def hex_to_group(hex_string, depth):
    # Check for "0x" prefix and remove it if present
    if hex_string.startswith("0x"):
        hex_string = hex_string[2:]

    first_two_bytes = hex_string[:4]  # Get the first four characters
    value = int(first_two_bytes, 16)  # Convert it to a decimal number
    group = value // (2 ** (16 - depth))  # Calculate the group based on depth
    return group

def generate_random_chunk(group, depth):
    while True:
        # Calculate the maximum span value based on the group and depth
        max_span_value = (group + 1) * (2 ** (16 - depth))

        # Generate a random span value within the calculated range
        span_value = random.randint(group * (2 ** (16 - depth)), max_span_value - 1)

        # Convert the span value to a little-endian 64-bit integer
        span = span_value.to_bytes(8, byteorder='little')

        # Generate random payload data for the chunk (up to MAX_CHUNK_PAYLOAD_SIZE bytes)
        max_payload_size = min(MAX_CHUNK_PAYLOAD_SIZE, 4096 - len(span))
        payload_size = random.randint(1, max_payload_size)
        payload = os.urandom(payload_size)

        # Use serialize_bytes to concatenate span and payload
        chunkContent = serialize_bytes(span, payload)

        # Calculate the BMT hash for the chunk
        chunk_hash = bmtHash(chunkContent)

        # Convert chunk_hash to a hexadecimal string
        chunk_hash_hex = chunk_hash.hex()

        # Check if the group from hex_to_group matches the desired group
        if hex_to_group(chunk_hash_hex, depth) == group:
            return {
                "group": group,
                "depth": depth,
                "span": span.hex(),
                "payload": payload.hex(),
                "chunk_hash": chunk_hash_hex
            }

def bmtRootHash(payload):
    if len(payload) > MAX_CHUNK_PAYLOAD_SIZE:
        raise ValueError('invalid data length')

    # Create an input buffer padded with zeros up to 4096 bytes (4KB)
    input_data = payload + b'\x00' * (MAX_CHUNK_PAYLOAD_SIZE - len(payload))

    while len(input_data) != HASH_SIZE:
        output = b''
        offset = 0

        # In each round, we hash the segment pairs together
        while offset < len(input_data):
            segment_pair = input_data[offset:offset + SEGMENT_PAIR_SIZE]
            hash_obj = keccak.new(data=segment_pair, digest_bits=256)
            output += hash_obj.digest()
            offset += SEGMENT_PAIR_SIZE

        input_data = output

    return input_data

def bmtHash(chunkContent):
    span = chunkContent[:8]
    payload = chunkContent[8:]
    rootHash = bmtRootHash(payload)

    # Use hashlib to calculate the final chunk hash
    chunkHashInput = span + rootHash
    chunk_hash = keccak.new(data=chunkHashInput, digest_bits=256).digest()

    return chunk_hash

def upload_chunk(chunk, upload_url):
    headers = {
        "Content-Type": "application/octet-stream"
    }
    
    response = requests.post(upload_url, data=chunk, headers=headers)
    return response

def main():
    parser = argparse.ArgumentParser(description='Generate random chunks and upload them to a server.')
    parser.add_argument('--depth', type=int, required=True, help='Depth parameter')
    parser.add_argument('--output', type=str, required=True, help='Output JSON file for generated data')
    parser.add_argument('--upload_url', type=str, required=True, help='URL for uploading data')

    args = parser.parse_args()

    depth = args.depth
    num_groups = 2 ** depth  # Calculate the number of groups

    random_chunks = []
    generated_groups = set()
    
    # Continue generating chunks until each group has one
    while len(generated_groups) < num_groups:
        group = random.randint(0, num_groups - 1)
    
        if group in generated_groups:
            continue
    
        random_chunk = generate_random_chunk(group, depth)
        random_chunks.append(random_chunk)
        generated_groups.add(group)

        # Upload the chunk individually
        payload_bytes = bytes.fromhex(random_chunk.get("payload"))
        response = upload_chunk(bytes.fromhex(random_chunk.get("span")) + payload_bytes, args.upload_url)

        if 200 <= response.status_code == 201:
            response_data = response.json()
            response_chunk_hash = response_data.get("reference", "")
            generated_chunk_hash = random_chunk["chunk_hash"]

            if response_chunk_hash == generated_chunk_hash:
                print(f'Successfully uploaded chunk {group} to the server.')
            else:
                print(f'Error: Chunk hash mismatch for chunk {group}.')
                print(f'Response: {response_chunk_hash}')
                print(f'generated: {generated_chunk_hash}')
        else:
            print(f'Error: Failed to upload chunk {group} to the server. Status code: {response.status_code}')

    # Save the generated data and responses to JSON files
    with open(args.output, 'w') as output_file:
        json.dump(random_chunks, output_file, indent=2)

    print(f'Generated data saved to {args.output}')

if __name__ == '__main__':
    main()
