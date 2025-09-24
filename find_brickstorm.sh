#!/bin/bash

# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script attempts to replicate the YARA rule G_APT_Backdoor_BRICKSTORM_3
# on systems without YARA installed.
#
# It checks for:
# 1. ELF file header (from `uint16(0) == 0x457F`)
# 2. A set of required strings (from `$str2` - `$str7`)
# 3. A specific hex pattern (from `$str1`)
#
# The condition is "all of them", so all checks must pass to flag a file.
#
# Usage: ./check_rule.sh /path/to/file1 /path/to/directory/

# --- START: OS-specific `find` compatibility ---
# Detect OS to set the correct flags for `find`
if [ "$(uname -s)" = "Linux" ]; then
    # GNU/Linux `find`
    FIND_OPTS="-L"                         # -L to follow links
    REGEX_EXPR="-regextype posix-extended" # Use -regextype as an expression
else
    # Assume BSD `find` (like on macOS/Darwin)
    FIND_OPTS="-LE"        # -L to follow links, -E to enable extended regex
    REGEX_EXPR=""          # No separate expression is needed
fi
# --- END: OS-specific `find` compatibility ---

# --- YARA Rule Definitions ---

# This regex corresponds to the hex string $str1.
# { 48 8B 05 ?? ?? ?? ?? 48 89 04 24 E8 ?? ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 04 24 [0-5] E8 ?? ?? ?? ?? EB ?? }
# The [0-5] means a 0-to-5 byte gap. In our hex dump, one
# byte is two characters ('..'). So, we use the regex (..){0,5}
hex_pattern="488b05........48890424e8........48b8................48890424(..){0,5}e8........eb.."

# This is $str7 ($long_num)
long_num="115792089210356248762697446949407573529996955224135760342422259061068512044369115792089210356248762697446949407573530086143415290314195533631308867097853951"
# --- End of Definitions ---


# Function to dynamically create a UTF-16LE (wide) regex pattern
# Usage: build_wide_pattern "text" -> "t\x00e\x00x\x00t\x00"
build_wide_pattern() {
    # sed: for each character (.), replace it with itself (&) followed by \x00
    echo -n "$1" | sed 's/./&\\x00/g'
}

# Function to check a single file
check_file() {
    local file="$1"
    
    # Ensure it's a file we can read
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        return
    fi

    # --- Condition 1: Check ELF Header ---
    # uint16(0) == 0x457F checks for the first two bytes being 0x7F 0x45
    # (little-endian), which is the start of an ELF file magic number.
    file_header=$(head -c 2 "$file" 2>/dev/null | xxd -p)
    if [ "$file_header" != "7f45" ]; then
        # Not an ELF file, so it cannot match.
        return
    fi

    # --- Condition 2: Check for all strings ($str2 - $str7) ---
    # We use `grep -iaPq` to search the binary (-a) case-insensitively (-i)
    # with Perl regex (-P) and stop on first match (-q).
    # We search for the ASCII string OR (|) the WIDE string.

    # $str2 "regex"
    str2="regex"
    str2_wide=$(build_wide_pattern "$str2")
    if ! grep -iaPq "$str2|$str2_wide" "$file"; then return; fi

    # $str3 "mime"
    str3="mime"
    str3_wide=$(build_wide_pattern "$str3")
    if ! grep -iaPq "$str3|$str3_wide" "$file"; then return; fi

    # $str4 "decompress"
    str4="decompress"
    str4_wide=$(build_wide_pattern "$str4")
    if ! grep -iaPq "$str4|$str4_wide" "$file"; then return; fi

    # $str5 "MIMEHeader"
    str5="MIMEHeader"
    str5_wide=$(build_wide_pattern "$str5")
    if ! grep -iaPq "$str5|$str5_wide" "$file"; then return; fi

    # $str6 "ResolveReference"
    str6="ResolveReference"
    str6_wide=$(build_wide_pattern "$str6")
    if ! grep -iaPq "$str6|$str6_wide" "$file"; then return; fi
    
    # $str7 (long_num)
    str7_wide=$(build_wide_pattern "$long_num")
    # -i is fine, even though it's numbers
    if ! grep -iaPq "$long_num|$str7_wide" "$file"; then return; fi

    # --- Condition 3: Check for hex string ($str1) ---
    # This is the most expensive check. We hex-dump the entire file,
    # remove newlines, and grep the resulting single line of hex.
    # We use grep -Pq for Perl-compatible regex to support (..){0,5}
    if ! xxd -p "$file" | tr -d '\n' | grep -Pq "$hex_pattern"; then
        return
    fi

    # --- All conditions met ---
    echo "MATCH: $file"
    echo "Found evidence of potential BRICKSTORM compromise."
    echo "You should consider performing a forensic investigation of the system."
    echo 
}

# --- Main script execution ---

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <file_or_directory1> [file_or_directory2] ..."
    echo "Checks files for strings and byte sequences present in the BRICKSTORM backdoor."
    exit 1
fi

# Export the function and variables so `find -exec` can use them
export -f check_file
export -f build_wide_pattern
export long_num
export hex_pattern

# Loop over all provided arguments
for target in "$@"; do
    if [ -d "$target" ]; then
        # If it's a directory, find all regular files and check them
        # Use the OS-specific flags from the top of the script
        find $FIND_OPTS "$target" $REGEX_EXPR -type f -size -10M \( -not -path "/proc/*" -and -not -regex "/tmp/[0-9]{10}/.*" -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" -and -not -regex "/var(/crash)?/log/notice.log" \) -exec bash -c 'check_file "$0"' {} \; 2>/dev/null
    elif [ -f "$target" ]; then
        # If it's a file, check it directly
        check_file "$target"
    else
        echo "Warning: '$target' is not a valid file or directory. Skipping." >&2
    fi
done