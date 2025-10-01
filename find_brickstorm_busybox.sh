#!/bin/sh

# This is a corrected "best effort" script for BusyBox environments.


# --- YARA Rule Definitions (used inside the find command below) ---
hex_pattern="488b05........48890424e8........48b8................48890424(..){0,5}e8........eb.."
long_num="115792089210356248762697446949407573529996955224135760342422259061068512044369115792089210356248762697446949407573530086143415290314195533631308867097853951"
# --- End of Definitions ---

# --- Main script execution ---
if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <file_or_directory1> [file_or_directory2] ..."
    exit 1
fi

find -L "$@" -type f -size -10000k \
    -not -path "/proc/*" \
    -not -regex ".*\/tmp\/[0-9]\{10\}\/.*" \
    -not -regex ".*\/var\/crash\/nsproflog\/newproflog.*" \
    -not -regex ".*\/var\/nsproflog\/newproflog.*" \
    -not -regex ".*\/var\/crash\/log\/notice\.log" \
    -not -regex ".*\/var\/log\/notice\.log" \
    -exec sh -c '
        file="$1"
        hex_pattern="488b05........48890424e8........48b8................48890424(..){0,5}e8........eb.."
        long_num="115792089210356248762697446949407573529996955224135760342422259061068512044369115792089210356248762697446949407573530086143415290314195533631308867097853951"
        
        # --- Start Check ---
        if [ ! -f "$file" ] || [ ! -r "$file" ]; then exit 0; fi

        file_header=$(head -c 2 "$file" 2>/dev/null | hexdump -v -e "/1 \"%02x\"")
        if [ "$file_header" != "7f45" ]; then exit 0; fi

        # ASCII string checks only.
        if ! grep -iaq "regex" "$file"; then exit 0; fi
        if ! grep -iaq "mime" "$file"; then exit 0; fi
        if ! grep -iaq "decompress" "$file"; then exit 0; fi
        if ! grep -iaq "MIMEHeader" "$file"; then exit 0; fi
        if ! grep -iaq "ResolveReference" "$file"; then exit 0; fi
        if ! grep -iaq "$long_num" "$file"; then exit 0; fi

        # Hex check using awk for portability.
        if ! hexdump -v -e "/1 \"%02x\"" "$file" 2>/dev/null | awk -v pat="$hex_pattern" "BEGIN{r=1} \$0 ~ pat {r=0; exit} END{exit r}"; then
            exit 0
        fi

        # --- All conditions met ---
        echo "MATCH: $file"
        echo "Found evidence of potential BRICKSTORM compromise."
        echo "You should consider performing a forensic investigation of the system."
        echo 
    ' _ {} \; 2>/dev/null