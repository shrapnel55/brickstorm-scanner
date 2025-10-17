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
    FIND_OPTS="-P"                         # -P to never follow symbolic links (avoids filesystem loops)
    REGEX_EXPR="-regextype posix-extended" # Use -regextype as an expression
else
    # Assume BSD `find` (like on macOS/Darwin)
    FIND_OPTS="-PE"        # -P to never follow symbolic links, -E to enable extended regex
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

# Function to count files that will be processed
count_files() {
    local target="$1"
    local count=0
    
    if [ -d "$target" ]; then
        # Count files in directory using the same find command as processing
        count=$(find $FIND_OPTS "$target" $REGEX_EXPR -type f -size -10M \( -not -path "/proc/*" -and -not -regex "/tmp/[0-9]{10}/.*" -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" -and -not -regex "/var(/crash)?/log/notice.log" \) 2>/dev/null | wc -l)
    elif [ -f "$target" ]; then
        # Single file
        count=1
    fi
    
    echo "$count"
}

# Function to count files with directory-level progress
count_files_with_progress() {
    local target="$1"
    local total_count=0
    
    if [ -d "$target" ]; then
        # Phase 1: Directory Discovery
        # First, check if there are any 2nd level directories
        local second_level_dirs=$(find $FIND_OPTS "$target" -maxdepth 2 -mindepth 2 -type d \( -not -path "/proc/*" -and -not -regex "/tmp/[0-9]{10}/.*" -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" -and -not -regex "/var(/crash)?/log/notice.log" \) 2>/dev/null)
        local second_level_count=$(echo "$second_level_dirs" | wc -l)
        
        local subdirs=""
        local total_dirs=0
        
        if [ "$second_level_count" -gt 0 ]; then
            # Use 2nd level directories for progress
            subdirs="$second_level_dirs"
            total_dirs=$second_level_count
        else
            # No 2nd level directories, use 1st level directories
            subdirs=$(find $FIND_OPTS "$target" -maxdepth 1 -type d \( -not -path "/proc/*" -and -not -regex "/tmp/[0-9]{10}/.*" -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" -and -not -regex "/var(/crash)?/log/notice.log" \) 2>/dev/null | tail -n +2)
            total_dirs=$(echo "$subdirs" | wc -l)
        fi
        
        # Always count files in the target directory itself first
        local root_count=$(find $FIND_OPTS "$target" -maxdepth 2 $REGEX_EXPR -type f -size -10M \( -not -path "/proc/*" -and -not -regex "/tmp/[0-9]{10}/.*" -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" -and -not -regex "/var(/crash)?/log/notice.log" \) 2>/dev/null | wc -l)
        total_count=$root_count
        
        if [ "$total_dirs" -eq 0 ]; then
            # No subdirectories, we're done
            :
        else
            # Phase 2: Chunked Processing
            local current_dir=0
            for dir in $subdirs; do
                local count=$(find $FIND_OPTS "$dir" $REGEX_EXPR -type f -size -10M \( -not -path "/proc/*" -and -not -regex "/tmp/[0-9]{10}/.*" -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" -and -not -regex "/var(/crash)?/log/notice.log" \) 2>/dev/null | wc -l)
                total_count=$((total_count + count))
                current_dir=$((current_dir + 1))
                show_progress "$current_dir" "$total_dirs" "Scanning directories" "$dir" >&2
            done
        fi
    elif [ -f "$target" ]; then
        # Single file
        total_count=1
    fi
    
    echo "$total_count"
}

# Function to show progress
show_progress() {
    local current="$1"
    local total="$2"
    local phase="$3"
    local dir_name="$4"  # Optional directory name
    
    if [ "$total" -eq 0 ]; then
        return
    fi
    
    local percentage=$((current * 100 / total))
    local bar_length=50
    local filled_length=$((current * bar_length / total))
    
    # Create progress bar
    local bar=""
    local i=0
    while [ $i -lt $bar_length ]; do
        if [ $i -lt $filled_length ]; then
            bar="${bar}█"
        else
            bar="${bar}░"
        fi
        i=$((i + 1))
    done
    
    # Print progress with carriage return to overwrite previous line
    if [ "$phase" = "Scanning directories" ]; then
        if [ -n "$dir_name" ]; then
            # Normalize directory name length (truncate or pad to 30 characters)
            local max_dir_len=30
            local normalized_dir=""
            if [ ${#dir_name} -gt $max_dir_len ]; then
                # Truncate long paths and add "..."
                normalized_dir="${dir_name:0:$((max_dir_len-3))}..."
            else
                # Pad short paths with spaces
                normalized_dir=$(printf "%-${max_dir_len}s" "$dir_name")
            fi
            printf "\r%s [%s] %d%% (%d/%d directories) - %s" "$phase" "$bar" "$percentage" "$current" "$total" "$normalized_dir"
        else
            printf "\r%s [%s] %d%% (%d/%d directories)" "$phase" "$bar" "$percentage" "$current" "$total"
        fi
    else
        printf "\r%s [%s] %d%% (%d/%d files)" "$phase" "$bar" "$percentage" "$current" "$total"
    fi
    
    # Force output flush
    printf ""
    
    # If we're done, add a newline
    if [ "$current" -eq "$total" ]; then
        echo
    fi
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
    if [ -n "$LOG_FILE" ]; then
        # If log file is set, tee output to both stdout and log file
        {
            echo "MATCH: $file"
            echo "Found evidence of potential BRICKSTORM compromise."
            echo "You should consider performing a forensic investigation of the system."
            echo 
        } | tee -a "$LOG_FILE"
    else
        # Otherwise, just echo to stdout
        echo "MATCH: $file"
        echo "Found evidence of potential BRICKSTORM compromise."
        echo "You should consider performing a forensic investigation of the system."
        echo 
    fi
}

# --- Main script execution ---

LOG_FILE=""

# Parse command-line options
while getopts ":o:" opt; do
  case $opt in
    o)
      LOG_FILE="$OPTARG"
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# Shift processed options away
shift $((OPTIND-1))

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 [-o /path/to/logfile] <file_or_directory1> [file_or_directory2] ..."
    echo "Checks files for strings and byte sequences present in the BRICKSTORM backdoor."
    exit 1
fi

# Check if log file is writable
if [ -n "$LOG_FILE" ]; then
    touch "$LOG_FILE" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "Error: Cannot write to log file: $LOG_FILE" >&2
        exit 1
    fi
    echo "Logging hits to: $LOG_FILE"
fi

# Export the function and variables so `find -exec` can use them
export -f check_file
export -f build_wide_pattern
export -f show_progress
export -f count_files_with_progress
export long_num
export hex_pattern
export LOG_FILE

# Record start time
start_time=$(date +%s)
start_timestamp=$(date)

# Count total files first with progress
total_files=0
echo "Scan started at: $start_timestamp"
echo "Counting files to scan..."
for target in "$@"; do
    if [ -d "$target" ] || [ -f "$target" ]; then
        # Run counting function - progress goes to stderr, count to stdout
        count=$(count_files_with_progress "$target")
        total_files=$((total_files + count))
    fi
done

if [ "$total_files" -eq 0 ]; then
    echo "No files to scan."
    exit 0
fi

echo "Found $total_files files to scan."
echo

# Process files with progress tracking
processed_files=0
progress_file=$(mktemp)

# Create a function that processes files and tracks progress
process_with_progress() {
    local file="$1"
    check_file "$file"
    # Increment counter in the progress file
    echo "1" >> "$progress_file"
    # Read current count and show progress
    local current=$(wc -l < "$progress_file" 2>/dev/null || echo "0")
    show_progress "$current" "$total_files" "Processing files"
}

# Export the progress function and variables
export -f process_with_progress
export total_files progress_file

for target in "$@"; do
    if [ -d "$target" ]; then
        # If it's a directory, find all regular files and check them
        # Use the OS-specific flags from the top of the script
        find $FIND_OPTS "$target" $REGEX_EXPR -type f -size -10M \( -not -path "/proc/*" -and -not -regex "/tmp/[0-9]{10}/.*" -and -not -regex "/var(/crash)?/nsproflog/newproflog.*" -and -not -regex "/var(/crash)?/log/notice.log" \) -exec bash -c 'process_with_progress "$0"' {} \; 2>/dev/null
    elif [ -f "$target" ]; then
        # If it's a file, check it directly
        process_with_progress "$target"
    else
        echo "Warning: '$target' is not a valid file or directory. Skipping." >&2
    fi
done

# Clean up progress file
rm -f "$progress_file"

# Record end time and calculate duration
end_time=$(date +%s)
end_timestamp=$(date)
duration=$((end_time - start_time))

# Format duration into human-readable format
if [ $duration -lt 60 ]; then
    duration_str="${duration}s"
elif [ $duration -lt 3600 ]; then
    minutes=$((duration / 60))
    seconds=$((duration % 60))
    duration_str="${minutes}m ${seconds}s"
else
    hours=$((duration / 3600))
    minutes=$(((duration % 3600) / 60))
    seconds=$((duration % 60))
    duration_str="${hours}h ${minutes}m ${seconds}s"
fi

echo
echo "Scan completed at: $end_timestamp"
echo "Total scan time: $duration_str"