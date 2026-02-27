#!/bin/bash
# CTBB Podcast Transcript Downloader
# Downloads transcripts from criticalthinkingpodcast.io episode pages
# Usage: ./get_transcripts.sh [output_dir]
#
# Reads links from links.txt in the same directory
# Saves each transcript as epXX.txt in the output directory

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LINKS_FILE="${SCRIPT_DIR}/links.txt"
OUTPUT_DIR="${1:-${SCRIPT_DIR}/transcripts}"

mkdir -p "$OUTPUT_DIR"

UA="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

echo "=== CTBB Transcript Downloader ==="
echo "Reading links from: $LINKS_FILE"
echo "Saving transcripts to: $OUTPUT_DIR"
echo ""

total=0
found=0
missing=0

while IFS= read -r url; do
  # Strip the #transcript anchor if present
  base_url=$(echo "$url" | sed 's/#transcript//')

  # Extract episode number from URL
  ep=$(echo "$url" | sed -E 's/.*episode-([0-9]+).*/\1/')

  if [ -z "$ep" ]; then
    echo "[SKIP] Could not extract episode number from: $url"
    continue
  fi

  total=$((total + 1))
  outfile="${OUTPUT_DIR}/ep${ep}.txt"

  # Skip if already downloaded
  if [ -f "$outfile" ] && [ -s "$outfile" ]; then
    existing_size=$(wc -c < "$outfile" | tr -d ' ')
    if [ "$existing_size" -gt 500 ]; then
      echo "[SKIP] EP $ep already downloaded (${existing_size} bytes)"
      found=$((found + 1))
      continue
    fi
  fi

  echo -n "[FETCH] EP $ep... "

  # Download the page HTML
  html=$(curl -s -L -A "$UA" "$base_url" 2>/dev/null)

  # Extract transcript using Python
  # The transcript can be in two formats:
  # 1. Inside <pre> tags with itemprop="transcript" (older episodes)
  # 2. Inside <p> tags with itemprop="transcript" (newer episodes)
  transcript=$(echo "$html" | python3 -c "
import sys, re, html as htmllib

data = sys.stdin.read()

# Method 1: Look for itemprop='transcript' with <pre> content
match = re.search(r'itemprop=\"transcript\">(.*?)</pre>', data, re.DOTALL)
if match:
    text = match.group(1)
    text = re.sub(r'<[^>]+>', '\n', text)
    text = htmllib.unescape(text)
    # Clean up multiple newlines
    text = re.sub(r'\n{3,}', '\n\n', text).strip()
    if len(text) > 100:
        print(text)
        sys.exit(0)

# Method 2: Look for itemprop='transcript' with <p> tag content
match = re.search(r'itemprop=\"transcript\">(.*?)</div>\s*</div>\s*</div>', data, re.DOTALL)
if match:
    text = match.group(1)
    # Replace <br> and <br/> with newlines
    text = re.sub(r'<br\s*/?>', '\n', text)
    # Replace </p><p> with double newlines
    text = re.sub(r'</p>\s*<p[^>]*>', '\n\n', text)
    # Strip remaining tags
    text = re.sub(r'<[^>]+>', '', text)
    text = htmllib.unescape(text)
    text = re.sub(r'\n{3,}', '\n\n', text).strip()
    if len(text) > 100:
        print(text)
        sys.exit(0)

# Method 3: Check id='transcript' div for any content
match = re.search(r'id=\"transcript\"[^>]*>(.*?)</div>', data, re.DOTALL)
if match:
    text = match.group(1)
    text = re.sub(r'<[^>]+>', '\n', text)
    text = htmllib.unescape(text)
    text = re.sub(r'\n{3,}', '\n\n', text).strip()
    if len(text) > 100:
        print(text)
        sys.exit(0)

print('NO_TRANSCRIPT')
" 2>/dev/null)

  if [ "$transcript" = "NO_TRANSCRIPT" ] || [ -z "$transcript" ]; then
    echo "NO TRANSCRIPT"
    missing=$((missing + 1))
    echo "" > "$outfile"
  else
    byte_count=$(echo "$transcript" | wc -c | tr -d ' ')
    echo "$transcript" > "$outfile"
    echo "OK (${byte_count} bytes)"
    found=$((found + 1))
  fi

  # Rate limiting
  sleep 1

done < "$LINKS_FILE"

echo ""
echo "=== Summary ==="
echo "Total episodes checked: $total"
echo "Transcripts found: $found"
echo "No transcript: $missing"
echo "Output directory: $OUTPUT_DIR"
