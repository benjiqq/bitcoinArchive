#!/usr/bin/env python3
"""
Extract all comments from Bitcoin source code files.
Handles both single-line (//) and multi-line (/* */) comments.
"""

import os
import re
from pathlib import Path

def extract_comments(filepath):
    """Extract all comments from a source file."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except Exception as e:
        return [{'error': str(e)}]

    comments = []
    in_multiline = False
    multiline_start = 0
    multiline_content = []

    for line_num, line in enumerate(lines, 1):
        original_line = line

        # Handle multi-line comments
        if in_multiline:
            multiline_content.append(line.rstrip())
            if '*/' in line:
                in_multiline = False
                comments.append({
                    'type': 'multi-line',
                    'start_line': multiline_start,
                    'end_line': line_num,
                    'content': '\n'.join(multiline_content)
                })
                multiline_content = []
            continue

        # Check for start of multi-line comment
        multiline_match = re.search(r'/\*', line)
        if multiline_match:
            in_multiline = True
            multiline_start = line_num
            multiline_content.append(line.rstrip())
            # Check if it ends on same line
            if '*/' in line[multiline_match.end():]:
                in_multiline = False
                comments.append({
                    'type': 'multi-line',
                    'start_line': line_num,
                    'end_line': line_num,
                    'content': line.rstrip()
                })
                multiline_content = []
            continue

        # Check for single-line comment
        single_match = re.search(r'//', line)
        if single_match:
            comment_text = line[single_match.start():].rstrip()
            comments.append({
                'type': 'single-line',
                'line': line_num,
                'content': comment_text
            })

    return comments

def main():
    # Define all files to process
    base_path = Path('/home/user/bitcoinArchive')

    # Bitcoin 0.1 source files
    bitcoin01_src = base_path / 'bitcoin0.1' / 'src'
    bitcoin01_files = [
        'db.cpp', 'headers.h', 'irc.cpp', 'main.cpp', 'main.h', 'market.cpp',
        'market.h', 'net.cpp', 'net.h', 'rpc.cpp', 'rpc.h', 'script.cpp',
        'script.h', 'serialize.h', 'sha.cpp', 'sha.h', 'ui.cpp', 'ui.h',
        'uibase.cpp', 'uibase.h', 'uint256.h', 'util.cpp', 'util.h',
        'base58.h', 'bignum.h', 'key.h'
    ]

    # Nov08 files
    nov08_path = base_path / 'nov08'
    nov08_files = ['main.cpp', 'main.h', 'node.cpp']

    # Study files
    study_path = base_path / 'study'
    study_files = ['main.cpp', 'db.cpp', 'irc.cpp', 'script.cpp', 'sha.cpp', 'net.cpp', 'util.cpp']

    # RPOW files
    rpow_base = base_path / 'precursor' / 'rpow-1.2.0'
    rpow_files = []
    for root, dirs, files in os.walk(rpow_base):
        for file in files:
            if file.endswith(('.c', '.h')):
                rpow_files.append(os.path.relpath(os.path.join(root, file), rpow_base))

    # Process all files
    results = []

    print("=" * 80)
    print("BITCOIN SOURCE CODE COMMENT EXTRACTION")
    print("=" * 80)
    print()

    # Process Bitcoin 0.1 files
    print("BITCOIN 0.1 SOURCE FILES")
    print("=" * 80)
    for filename in bitcoin01_files:
        filepath = bitcoin01_src / filename
        if filepath.exists():
            print(f"\nFile: {filepath}")
            print("-" * 80)
            comments = extract_comments(filepath)
            if comments:
                for comment in comments:
                    if 'error' in comment:
                        print(f"ERROR: {comment['error']}")
                    elif comment['type'] == 'single-line':
                        print(f"[Line {comment['line']}] Single-line comment:")
                        print(f"  {comment['content']}")
                    else:
                        print(f"[Lines {comment['start_line']}-{comment['end_line']}] Multi-line comment:")
                        for line in comment['content'].split('\n'):
                            print(f"  {line}")
            else:
                print("  No comments found")

    # Process Nov08 files
    print("\n\n" + "=" * 80)
    print("NOV08 FILES")
    print("=" * 80)
    for filename in nov08_files:
        filepath = nov08_path / filename
        if filepath.exists():
            print(f"\nFile: {filepath}")
            print("-" * 80)
            comments = extract_comments(filepath)
            if comments:
                for comment in comments:
                    if 'error' in comment:
                        print(f"ERROR: {comment['error']}")
                    elif comment['type'] == 'single-line':
                        print(f"[Line {comment['line']}] Single-line comment:")
                        print(f"  {comment['content']}")
                    else:
                        print(f"[Lines {comment['start_line']}-{comment['end_line']}] Multi-line comment:")
                        for line in comment['content'].split('\n'):
                            print(f"  {line}")
            else:
                print("  No comments found")

    # Process Study files
    print("\n\n" + "=" * 80)
    print("STUDY FILES")
    print("=" * 80)
    for filename in study_files:
        filepath = study_path / filename
        if filepath.exists():
            print(f"\nFile: {filepath}")
            print("-" * 80)
            comments = extract_comments(filepath)
            if comments:
                for comment in comments:
                    if 'error' in comment:
                        print(f"ERROR: {comment['error']}")
                    elif comment['type'] == 'single-line':
                        print(f"[Line {comment['line']}] Single-line comment:")
                        print(f"  {comment['content']}")
                    else:
                        print(f"[Lines {comment['start_line']}-{comment['end_line']}] Multi-line comment:")
                        for line in comment['content'].split('\n'):
                            print(f"  {line}")
            else:
                print("  No comments found")

    # Process RPOW files
    print("\n\n" + "=" * 80)
    print("RPOW FILES")
    print("=" * 80)
    for filename in sorted(rpow_files):
        filepath = rpow_base / filename
        if filepath.exists():
            print(f"\nFile: {filepath}")
            print("-" * 80)
            comments = extract_comments(filepath)
            if comments:
                for comment in comments:
                    if 'error' in comment:
                        print(f"ERROR: {comment['error']}")
                    elif comment['type'] == 'single-line':
                        print(f"[Line {comment['line']}] Single-line comment:")
                        print(f"  {comment['content']}")
                    else:
                        print(f"[Lines {comment['start_line']}-{comment['end_line']}] Multi-line comment:")
                        for line in comment['content'].split('\n'):
                            print(f"  {line}")
            else:
                print("  No comments found")

    print("\n\n" + "=" * 80)
    print("EXTRACTION COMPLETE")
    print("=" * 80)

if __name__ == '__main__':
    main()
