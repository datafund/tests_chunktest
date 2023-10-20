#!/bin/python3
import os
import random
import argparse
import json
import requests
import hashlib
import time
import signal
import sys
import prometheus_client
from Crypto.Hash import keccak
from prometheus_client import CollectorRegistry, Summary, Histogram, push_to_gateway
from prometheus_client.exposition import basic_auth_handler

MAX_CHUNK_PAYLOAD_SIZE = 4096
SEGMENT_SIZE = 32
SEGMENT_PAIR_SIZE = 2 * SEGMENT_SIZE
HASH_SIZE = 32

prometheus_client.REGISTRY.unregister(prometheus_client.GC_COLLECTOR)
prometheus_client.REGISTRY.unregister(prometheus_client.PLATFORM_COLLECTOR)
prometheus_client.REGISTRY.unregister(prometheus_client.PROCESS_COLLECTOR)

def pgw_auth_handler(url, method, timeout, headers, data):
    username = 'datafund'
    password = os.getenv('PGW_PW')
    return basic_auth_handler(url, method, timeout, headers, data, username, password)

registry = CollectorRegistry()
DL_TIME = Summary('datafund_chunktest_download_time',
                       'Time spent processing request',
                       labelnames=['status', 'group'],
                       registry=registry)

UL_TIME = Summary('datafund_chunktest_upload_time',
                       'Time spent processing request',
                       labelnames=['status', 'group'],
                       registry=registry)

DL_TIME_HISTOGRAM = Histogram(
    'datafund_chunktest_download_time_histogram',
    'Time consumed per chunk downloaded',
    labelnames=['status', 'group'],
    registry=registry,
)

UL_TIME_HISTOGRAM = Histogram(
    'datafund_chunktest_upload_time_histogram',
    'Time consumed per chunk uploaded',
    labelnames=['status', 'group'],
    registry=registry,
)


def signal_handler(sig, frame):
    global args
    # This function will be called when Ctrl+C is pressed
    print("Ctrl+C pressed. Cleaning up or running specific code...")
    cleanup_prometheus(args)
    push_to_gateway(args.prometheus_push_url, job='chunktest', registry=registry, handler=pgw_auth_handler)
    sys.exit(0)  # Exit the script gracefully

def cleanup_prometheus(args):
    DL_TIME.clear()
    UL_TIME.clear()
    DL_TIME_HISTOGRAM.clear()
    UL_TIME_HISTOGRAM.clear()
    push_to_gateway(args.prometheus_push_url, job='chunktest', registry=registry, handler=pgw_auth_handler)

def serialize_bytes(*arrays):
    length = sum(len(arr) for arr in arrays)
    buffer = bytearray(length)
    offset = 0
    for arr in arrays:
        buffer[offset:offset + len(arr)] = arr
        offset += len(arr)
    return buffer

def hex_to_group(hex_string, depth):
    if hex_string.startswith("0x"):
        hex_string = hex_string[2:]
    first_two_bytes = hex_string[:4]
    value = int(first_two_bytes, 16)
    group = value // (2 ** (16 - depth))
    return group

def generate_random_chunk(group, depth):
    while True:
        max_span_value = (group + 1) * (2 ** (16 - depth))
        span_value = random.randint(group * (2 ** (16 - depth)), max_span_value - 1)
        span = span_value.to_bytes(8, byteorder='little')

        max_payload_size = min(MAX_CHUNK_PAYLOAD_SIZE, 4096 - len(span))
        payload_size = random.randint(1, max_payload_size)
        payload = os.urandom(payload_size)

        chunkContent = serialize_bytes(span, payload)
        chunk_hash = bmtHash(chunkContent)

        chunk_hash_hex = chunk_hash.hex()

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
    input_data = payload + b'\x00' * (MAX_CHUNK_PAYLOAD_SIZE - len(payload))
    while len(input_data) != HASH_SIZE:
        output = b''
        offset = 0
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
    chunkHashInput = span + rootHash
    chunk_hash = keccak.new(data=chunkHashInput, digest_bits=256).digest()
    return chunk_hash

def upload_chunk(chunk, url):
    headers = {
        "Content-Type": "application/octet-stream"
    }
    
    response = requests.post(url, data=chunk, headers=headers)
    return response

def main(args):

    depth = args.depth
    num_groups = 2 ** depth

    if args.upload:
        # Generate random chunks and upload them
        random_chunks = []
        generated_groups = set()
        upload_histogram = Histogram('upload_chunk_duration_seconds', 'Upload Chunk Duration in Seconds', ['group', 'status'])

        while len(generated_groups) < num_groups:
            group = random.randint(0, num_groups - 1)

            if group in generated_groups:
                continue

            start_time = time.time()
            random_chunk = generate_random_chunk(group, depth)
            end_time = time.time()
            duration = end_time - start_time

            labels = {'group': str(group), 'status': 'success'}
            upload_histogram.labels(**labels).observe(duration)

            random_chunks.append(random_chunk)
            generated_groups.add(group)

            payload_bytes = bytes.fromhex(random_chunk.get("payload"))
            response = upload_chunk(bytes.fromhex(random_chunk.get("span")) + payload_bytes, args.url)

            if 200 <= response.status_code == 201:
                response_data = response.json()
                response_chunk_hash = response_data.get("reference", "")
                generated_chunk_hash = random_chunk["chunk_hash"]

                if response_chunk_hash == generated_chunk_hash:
                    print(f'Successfully uploaded chunk {group} to the server.')
                else:
                    print(f'Error: Chunk hash mismatch for chunk {group}.')
                    print(f'Response: {response_chunk_hash}')
                    print(f'Generated: {generated_chunk_hash}')
            else:
                print(f'Error: Failed to upload chunk {group} to the server. Status code: {response.status_code}')

        with open('chunks.json', 'w') as output_file:
            json.dump(random_chunks, output_file, indent=2)

        print('Generated data saved to chunks.json')

    if args.download:
        # Download chunks using URLs from chunks.json
        while True:
            try:
                with open('chunks.json', 'r') as input_file:
                    chunks = json.load(input_file)
    
                for chunk in chunks:
                    start_time = time.time()
                    download_url = f'{args.url}/{chunk["chunk_hash"]}'
                    response = requests.get(download_url)
    
                    if response.status_code == 200:
                        print(f'Successfully downloaded chunk {chunk["group"]}')
                    else:
                        print(f'Error: Failed to download chunk {chunk["group"]}. Status code: {response.status_code}')
    
                    end_time = time.time()  # Record the end time
                    duration = end_time - start_time
                    DL_TIME_HISTOGRAM.labels(status=response.status_code, group=chunk["group"]).observe(duration)
                    DL_TIME.labels(status=response.status_code, group=chunk["group"]).observe(duration)
    
                push_to_gateway(args.prometheus_push_url, job='chunktest', registry=registry, handler=pgw_auth_handler)
                time.sleep(60)  # Sleep for 60 seconds between download cycles
                cleanup_prometheus(args)
            except requests.exceptions.RequestException as e:
                print(f'An error occurred during download: {str(e)}')
                time.sleep(60)  # Sleep for 60 seconds before retrying
            except Exception as e:
                print(f'An unexpected error occurred: {str(e)}')
                break  # Exit the loop on unexpected errors


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate random chunks and upload them to a server.')
    parser.add_argument('--upload', action='store_true', help='Generate and upload chunks')
    parser.add_argument('--depth', type=int, help='Depth parameter', default=10)
    parser.add_argument('--download', action='store_true', help='Download chunks from URLs')
    parser.add_argument('--url', type=str, help='URL for uploading data')
    parser.add_argument('--prometheus_push_url', type=str, help='Push URL for Prometheus metrics', default='https://pgw.datafund.io')

    args = parser.parse_args()
    # Set up the signal handler
    signal.signal(signal.SIGINT, signal_handler)
    main(args)
    push_to_gateway(args.prometheus_push_url, job='chunktest', registry=registry, handler=pgw_auth_handler)
    time.sleep(10)
    cleanup_prometheus(args)


