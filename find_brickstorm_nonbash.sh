#!/bin/sh

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

# --- START: OS-specific `find` compatibility ---
# Detect OS to set the correct flags for `find`
if [ "$(uname -s)" = "Linux" ]; then
    # GNU/Linux `find`
    FIND_OPTS="-L"
    REGEX_EXPR="-regextype posix-extended"
else
    # Assume BSD `find` (like on macOS/Darwin)
    FIND_OPTS="-LE"
    REGEX_EXPR=""
fi
# --- END: OS-specific `find` compatibility ---

# --- YARA Rule Definitions ---
hex_pattern="488b05........48890424e8........48b8................48890424(..){0,5}e8........eb.."
long_num="115792089210356248762697446949407573529996955224135760342422259061068512044369115792089210356248762697446949407573530086143415290314195533631308867097853951"
# --- End of Definitions ---

build_wide_pattern() {
    echo -n "$1" | sed 's/./&\\x00/g'
}

check_file() {
    # NOTE: `local` keyword removed for sh compatibility
    file="$1"
    
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        return
    fi

    file_header=$(head -c 2 "$file" 2>/dev/null | xxd -p)
    if [ "$file_header" != "7f45" ]; then
        return
    fi

    str2="regex"
    str2_wide=$(build_wide_pattern "$str2")
    if ! grep -iaPq "$str2|$str2_wide" "$file"; then return; fi

    str3="mime"
    str3_wide=$(build_wide_pattern "$str3")
    if ! grep -iaPq "$str3|$str3_wide" "$file"; then return; fi

    str4="decompress"
    str4_wide=$(build_wide_pattern "$str4")
    if ! grep -iaPq "$str4|$str4_wide" "$file"; then return; fi

    str5="MIMEHeader"
    str5_wide=$(build_wide_pattern "$str5")
    if ! grep -iaPq "$str5|$str5_wide" "$file"; then return; fi

    str6="ResolveReference"
    str6_wide=$(build_wide_pattern "$str6")
    if ! grep -iaPq "$str6|$str6_wide" "$file"; then return; fi
    
    str7_wide=$(build_wide_pattern "$long_num")
    if ! grep -iaPq "$long_num|$str7_wide" "$file"; then return; fi

    if ! xxd -p "$file" | tr -d '\n' | grep -Pq "$hex_pattern"; then
        return
    fi

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

# The main loop is now a `find | while read` pipe.
# We removed `-print0` from find and `-d ''` from read for sh compatibility.
# This version will not work with filenames containing newlines.
find $FIND_OPTS "$@" $REGEX_EXPR -type f -size -10M \( -not -path "/proc/*" -and -not -regex "/tmp/[0-9]{10}/.*" -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" -and -not -regex "/var(/crash)?/log/notice.log" \) 2>/dev/null |
while IFS= read -r file; do
    check_file "$file"
done
