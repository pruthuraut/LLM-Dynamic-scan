#!/usr/bin/env python3
"""
Prompt injection tester

Reads payloads from a text file and sends them to an LLM endpoint, logging
request payloads and responses for later analysis.

Usage examples are in the repository README.
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import Dict, List

import requests


def parse_headers(header_list: List[str]) -> Dict[str, str]:
    headers = {}
    for h in header_list or []:
        if ':' in h:
            name, val = h.split(':', 1)
            headers[name.strip()] = val.strip()
        else:
            print(f"Ignoring malformed header: {h}")
    return headers


def load_payloads(path: str) -> List[str]:
    with open(path, 'r', encoding='utf-8') as f:
        lines = [l.rstrip('\n') for l in f]
    payloads = []
    for l in lines:
        s = l.strip()
        if not s:
            continue
        if s.startswith('#'):
            continue
        payloads.append(s)
    return payloads


def make_body(template: str, field: str, payload: str):
    if template:
        try:
            body_text = template.replace('{payload}', payload)
            return json.loads(body_text)
        except Exception:
            # fallback: send template as raw string with substitution
            return body_text
    else:
        return {field: payload}


def main():
    parser = argparse.ArgumentParser(description='Send prompt-injection payloads to an LLM endpoint')
    parser.add_argument('--endpoint', '-e', required=True, help='LLM HTTP(S) endpoint URL')
    parser.add_argument('--payload-file', '-p', default='payloads.txt', help='Text file with payloads (one per line)')
    parser.add_argument('--output-dir', '-o', default='pi_results', help='Directory to write logs')
    parser.add_argument('--header', '-H', action='append', help='Extra header, use multiple times, e.g. "Authorization: Bearer ..."')
    parser.add_argument('--method', '-m', default='POST', choices=['POST', 'GET'], help='HTTP method to use')
    parser.add_argument('--json-field', default='input', help='Default JSON field name for payload when no template is used')
    parser.add_argument('--json-template', default='', help='JSON template containing {payload} placeholder, e.g. "{\"messages\":[{\"role\":\"user\",\"content\":\"{payload}\"}]}"')
    parser.add_argument('--timeout', type=int, default=60, help='Request timeout in seconds')
    parser.add_argument('--delay', type=float, default=0.5, help='Delay between requests in seconds')
    parser.add_argument('--insecure', action='store_true', help='Disable SSL verification')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    requests_log = os.path.join(args.output_dir, 'requests.log')
    responses_log = os.path.join(args.output_dir, 'responses.log')
    results_jsonl = os.path.join(args.output_dir, 'results.jsonl')

    headers = parse_headers(args.header)
    # default JSON content-type if not provided and sending JSON
    if args.method == 'POST' and 'Content-Type' not in headers:
        headers.setdefault('Content-Type', 'application/json')

    try:
        payloads = load_payloads(args.payload_file)
    except FileNotFoundError:
        print(f"Payload file not found: {args.payload_file}")
        sys.exit(2)

    total = len(payloads)
    if total == 0:
        print('No payloads found in file.')
        sys.exit(0)

    print(f"Sending {total} payloads to {args.endpoint}")

    with open(requests_log, 'w', encoding='utf-8') as req_f, \
         open(responses_log, 'w', encoding='utf-8') as resp_f, \
         open(results_jsonl, 'w', encoding='utf-8') as out_f:

        for idx, payload in enumerate(payloads, start=1):
            rec = {'id': idx, 'payload': payload, 'timestamp': datetime.utcnow().isoformat() + 'Z'}
            # write payload to requests log
            req_f.write(json.dumps(rec, ensure_ascii=False) + '\n')
            req_f.flush()

            body = make_body(args.json_template, args.json_field, payload)

            try:
                start = time.time()
                if args.method == 'POST':
                    if isinstance(body, str):
                        data = body.encode('utf-8')
                        resp = requests.post(args.endpoint, headers=headers, data=data, timeout=args.timeout, verify=not args.insecure)
                    else:
                        resp = requests.post(args.endpoint, headers=headers, json=body, timeout=args.timeout, verify=not args.insecure)
                else:
                    # GET
                    params = {args.json_field: payload}
                    resp = requests.get(args.endpoint, headers=headers, params=params, timeout=args.timeout, verify=not args.insecure)
                elapsed = time.time() - start

                response_record = {
                    'id': idx,
                    'status_code': resp.status_code,
                    'elapsed_sec': round(elapsed, 3),
                    'headers': dict(resp.headers),
                    'text': resp.text,
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                }

            except Exception as e:
                response_record = {
                    'id': idx,
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                }

            # write response to responses log and combined jsonl
            resp_f.write(json.dumps(response_record, ensure_ascii=False) + '\n')
            resp_f.flush()

            combined = {'id': idx, 'payload': payload, 'response': response_record}
            out_f.write(json.dumps(combined, ensure_ascii=False) + '\n')
            out_f.flush()

            if args.verbose:
                print(f"{idx}/{total} -> status: {response_record.get('status_code')}, elapsed: {response_record.get('elapsed_sec')}")

            # polite delay
            if idx != total and args.delay:
                time.sleep(args.delay)

    print(f"Done. Results in {args.output_dir} (results.jsonl, requests.log, responses.log)")


if __name__ == '__main__':
    main()
