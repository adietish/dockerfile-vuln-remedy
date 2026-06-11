#!/usr/bin/env bash
set -euo pipefail

# dockerfile-vuln-remediator.sh - Scan Dockerfile base images and suggest pinned upgrade tags

declare -r SCRIPT_NAME="dockerfile-vuln-remediator"
declare -r SCRIPT_VERSION="0.0.1"

# Color codes
declare -r RED='\033[0;31m'
declare -r YELLOW='\033[1;33m'
declare -r GREEN='\033[0;32m'
declare -r BLUE='\033[0;34m'
declare -r CYAN='\033[0;36m'
declare -r BOLD='\033[1m'
declare -r DIM='\033[2m'
declare -r NC='\033[0m' # No Color

# Global associative arrays for FROM tracking
declare -A FROM_MAP      # Maps FROM name -> base image
declare -A FROM_DEPS     # Maps FROM name -> space-separated list of dependency FROMs
declare -A IMAGE_LINES   # Maps image_ref -> line number in Dockerfile
declare FINAL_FROM=""    # Name of the final FROM
declare -a RELEVANT_IMAGES=()  # Array of images that contribute to final image
declare -A IMAGE_CACHE   # Maps image_ref -> API response cache
declare -a VULNS         # Array of vulnerabilities: CVE_ID|severity|package|image_ref|description
declare SHOW_ALL=false   # Show all severities (default: only Critical and High)
declare -a REMEDIATIONS  # Array of remediation suggestions
declare -a PATCH_ENTRIES  # Array of "line_num|old_image_ref|new_image_ref" for patch generation
declare PATCH_MODE=false  # Generate patch file if true
declare DOCKERFILE_PATH="" # Path to Dockerfile to analyze


# --- Terminal Output Helpers ---
print_ruler() {
    local width="${1:-78}"
    printf '%*s\n' "$width" '' | tr ' ' '-'
}

print_section() {
    echo ""
    echo -e "${BOLD}${BLUE}$1${NC}"
    print_ruler
}

print_kv() {
    printf "  %-20s %s\n" "$1" "$2"
}

# --- Dependency Check ---
check_dependencies() {
    local missing_deps=()
    local required_deps=("curl" "jq")

    for dep in "${required_deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_deps+=("$dep")
        fi
    done

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo "Error: Missing required dependencies: ${missing_deps[*]}" >&2
        echo "Please install the missing tools and try again." >&2
        return 1
    fi

    return 0
}

# --- Help and Version ---
show_help() {
    cat << EOF
${SCRIPT_NAME} - Scan Dockerfile base images and suggest pinned upgrade tags

Queries Red Hat Pyxis for vulnerabilities in FROM images and recommends newer
pinned tags (e.g. 1-1781041605) that resolve reported CVEs.

Usage: ${SCRIPT_NAME}.sh <DOCKERFILE> [OPTIONS]

Arguments:
    DOCKERFILE           Path to the Dockerfile to scan (required)

Options:
    --show-all           Show all severities (default: only Critical and High)
    --patch              Generate a patch file (Dockerfile.patch) with suggested FROM line changes; apply with: patch -p0 < Dockerfile.patch
    --help               Show this help message
    --version            Show version information

Examples:
    ${SCRIPT_NAME}.sh ./Dockerfile
    ${SCRIPT_NAME}.sh ./Dockerfile --show-all
    ${SCRIPT_NAME}.sh ./Dockerfile --patch
EOF
}

show_version() {
    echo "${SCRIPT_NAME} v${SCRIPT_VERSION}"
}

# --- Argument Parsing ---
parse_args() {
    # First positional argument is the Dockerfile path
    if [[ $# -gt 0 && "$1" != --* ]]; then
        DOCKERFILE_PATH="$1"
        shift
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --show-all)
                SHOW_ALL=true
                shift
                ;;
            --patch)
                PATCH_MODE=true
                shift
                ;;
            --help)
                show_help
                exit 0
                ;;
            --version)
                show_version
                exit 0
                ;;
            *)
                echo "Error: Unknown option: $1" >&2
                echo "Use --help for usage information." >&2
                exit 1
                ;;
        esac
    done
}

# --- Dockerfile Parsing ---
parse_dockerfile() {
    local dockerfile="$1"

    if [[ ! -f "$dockerfile" ]]; then
        echo "Error: Dockerfile not found: $dockerfile" >&2
        exit 1
    fi

    local from_counter=0
    local current_from=""
    local line_number=0

    # Parse FROM statements
    while IFS= read -r line; do
        line_number=$((line_number + 1))

        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue

        # Match FROM statements: FROM <image> [AS <from>]
        # Use case-insensitive matching by converting only the keywords to uppercase for comparison
        local line_upper="${line^^}"
        if [[ "$line_upper" =~ ^[[:space:]]*FROM[[:space:]]+ ]]; then
            # Extract image and optional FROM name from original line (preserves case)
            if [[ "$line" =~ ^[[:space:]]*[Ff][Rr][Oo][Mm][[:space:]]+([^[:space:]]+)([[:space:]]+[Aa][Ss][[:space:]]+([^[:space:]]+))? ]]; then
                local image="${BASH_REMATCH[1]}"
                local from_name="${BASH_REMATCH[3]}"

                # Auto-generate FROM name if not specified
                if [[ -z "$from_name" ]]; then
                    from_name="from${from_counter}"
                fi

                FROM_MAP["$from_name"]="$image"
                IMAGE_LINES["$image"]="$line_number"
                current_from="$from_name"
                from_counter=$((from_counter + 1))
            fi
        fi

        # Match COPY --from=<from> statements
        if [[ "$line_upper" =~ ^[[:space:]]*COPY[[:space:]]+--FROM= ]]; then
            # Extract the FROM name from original line
            if [[ "$line" =~ ^[[:space:]]*[Cc][Oo][Pp][Yy][[:space:]]+--[Ff][Rr][Oo][Mm]=([^[:space:]]+) ]]; then
                local from_ref="${BASH_REMATCH[1]}"

                # Add to dependencies if we have a current FROM
                if [[ -n "$current_from" ]]; then
                    if [[ -z "${FROM_DEPS[$current_from]:-}" ]]; then
                        FROM_DEPS["$current_from"]="$from_ref"
                    else
                        FROM_DEPS["$current_from"]+=" $from_ref"
                    fi
                fi
            fi
        fi
    done < "$dockerfile"

    # Check if we found any FROM statements
    if [[ ${#FROM_MAP[@]} -eq 0 ]]; then
        echo "Error: No FROM statements found in Dockerfile" >&2
        exit 1
    fi

    # Identify final FROM (last one defined)
    FINAL_FROM="$current_from"

    echo -e "${CYAN}Parsed ${#FROM_MAP[@]} FROMs from Dockerfile${NC}" >&2
    echo -e "${CYAN}Final FROM: ${FINAL_FROM}${NC}" >&2
}

# --- From Dependency Tracing ---
trace_from_dependencies() {
    local -A visited
    local -a to_visit

    # Start from final FROM
    to_visit=("$FINAL_FROM")

    # Breadth-first traversal
    while [[ ${#to_visit[@]} -gt 0 ]]; do
        local current="${to_visit[0]}"
        to_visit=("${to_visit[@]:1}")  # Remove first element

        # Skip if already visited
        [[ -n "${visited[$current]:-}" ]] && continue
        visited["$current"]=1

        # Add current FROM's image to relevant images
        if [[ -n "${FROM_MAP[$current]}" ]]; then
            RELEVANT_IMAGES+=("${FROM_MAP[$current]}")
        else
            echo "Warning: From '$current' referenced but not defined" >&2
        fi

        # Add dependencies to visit queue
        if [[ -n "${FROM_DEPS[$current]:-}" ]]; then
            for dep in ${FROM_DEPS[$current]}; do
                if [[ -z "${visited[$dep]:-}" ]]; then
                    to_visit+=("$dep")
                fi
            done
        fi
    done

    # Remove duplicates from RELEVANT_IMAGES
    local -A unique_images
    local -a deduplicated
    for img in "${RELEVANT_IMAGES[@]}"; do
        if [[ -z "${unique_images[$img]:-}" ]]; then
            unique_images["$img"]=1
            deduplicated+=("$img")
        fi
    done
    RELEVANT_IMAGES=("${deduplicated[@]}")

    echo -e "${CYAN}Traced ${#RELEVANT_IMAGES[@]} relevant images${NC}" >&2
}

# --- Image Reference Parsing ---
parse_image_reference() {
    local image_ref="$1"
    local registry repo tag

    # Extract registry, repository, and tag
    # Format: registry.example.com/repo/subpath:tag

    # Split by first /
    if [[ "$image_ref" =~ ^([^/]+)/(.+)$ ]]; then
        registry="${BASH_REMATCH[1]}"
        local remainder="${BASH_REMATCH[2]}"

        # Split remainder by :
        if [[ "$remainder" =~ ^(.+):([^:]+)$ ]]; then
            repo="${BASH_REMATCH[1]}"
            tag="${BASH_REMATCH[2]}"
        else
            repo="$remainder"
            tag="latest"
        fi
    else
        # No registry specified (e.g., "ubuntu:22.04")
        registry="docker.io"
        if [[ "$image_ref" =~ ^(.+):([^:]+)$ ]]; then
            repo="${BASH_REMATCH[1]}"
            tag="${BASH_REMATCH[2]}"
        else
            repo="$image_ref"
            tag="latest"
        fi
    fi

    echo "${registry}|${repo}|${tag}"
}

# --- API Query Functions ---

rh_curl() {
    curl -s -f "$@"
}

rate_limit_sleep() {
    sleep 0.$(( (RANDOM % 4) + 2 ))
}

query_image_metadata() {
    local image_ref="$1"
    local result_var="${2:-_QUERY_IMAGE_METADATA_RESULT}"
    local image_id="" repo_id=""

    if [[ -n "${IMAGE_CACHE[$image_ref]:-}" ]]; then
        if [[ "${IMAGE_CACHE[$image_ref]}" == *:* ]]; then
            image_id="${IMAGE_CACHE[$image_ref]%%:*}"
            repo_id="${IMAGE_CACHE[$image_ref]##*:}"
        else
            image_id="${IMAGE_CACHE[$image_ref]}"
        fi
        printf -v "$result_var" "${image_id}|${repo_id}"
        return 0
    fi

    local parsed
    parsed=$(parse_image_reference "$image_ref")
    IFS='|' read -r registry repo tag <<< "$parsed"

    echo "Querying metadata for: ${registry}/${repo}:${tag}" >&2

    if [[ ! "$registry" =~ registry\.access\.redhat\.com|registry\.redhat\.io|quay\.io/redhat ]]; then
        echo "Warning: Skipping non-Red Hat registry: $registry" >&2
        IMAGE_CACHE["$image_ref"]="NON_REDHAT"
        printf -v "$result_var" "NON_REDHAT|"
        return 0
    fi

    local api_url="https://catalog.redhat.com/api/containers/v1/images"
    api_url+="?filter=repositories.registry==${registry}"
    api_url+="&filter=repositories.repository==${repo}"
    api_url+="&filter=repositories.tags.name==${tag}"
    api_url+="&page_size=1"

    local response
    rate_limit_sleep
    response=$(rh_curl "$api_url" 2>&1)
    local curl_exit=$?

    if [[ $curl_exit -ne 0 ]]; then
        echo "Warning: Failed to query metadata for ${image_ref}: $response" >&2
        IMAGE_CACHE["$image_ref"]="ERROR"
        printf -v "$result_var" "ERROR|"
        return 0
    fi

    image_id=$(echo "$response" | jq -r '.data[0]._id // empty' 2>/dev/null || echo "")

    if [[ -z "$image_id" || "$image_id" == "null" ]]; then
        echo "Warning: No image ID found for ${image_ref}" >&2
        IMAGE_CACHE["$image_ref"]="NOT_FOUND"
        printf -v "$result_var" "NOT_FOUND|"
        return 0
    fi

    local repo_encoded
    repo_encoded=$(printf '%s' "$repo" | jq -sRr @uri)
    local repo_api_url="https://catalog.redhat.com/api/containers/v1/repositories/registry/${registry}/repository/${repo_encoded}"
    local repo_response
    rate_limit_sleep
    repo_response=$(rh_curl "$repo_api_url" 2>&1) || true
    if echo "$repo_response" | jq -e 'has("_id")' > /dev/null 2>&1; then
        repo_id=$(echo "$repo_response" | jq -r '._id // empty' 2>/dev/null || echo "")
    else
        repo_id=""
    fi

    if [[ -n "$repo_id" ]]; then
        IMAGE_CACHE["$image_ref"]="${image_id}:${repo_id}"
    else
        IMAGE_CACHE["$image_ref"]="$image_id"
    fi

    printf -v "$result_var" "${image_id}|${repo_id}"
}

query_vulnerabilities() {
    local image_ref="$1"
    local image_id="$2"

    echo "Querying vulnerabilities for: ${image_ref}" >&2

    # Query Pyxis API for vulnerabilities (NO AUTH HEADER)
    local api_url="https://catalog.redhat.com/api/containers/v1/images/id/${image_id}/vulnerabilities"

    local response
    rate_limit_sleep
    response=$(rh_curl "$api_url" 2>&1)
    local curl_exit=$?

    if [[ $curl_exit -ne 0 ]]; then
        echo "Warning: Failed to query vulnerabilities for ${image_ref}: $response" >&2
        return 1
    fi

    if ! echo "$response" | jq -e '.data | type == "array"' > /dev/null 2>&1; then
        echo "Warning: Unexpected API response shape for ${image_ref}" >&2
        return 1
    fi

    local cve_count
    cve_count=$(echo "$response" | jq -r '.data | length' 2>/dev/null || echo "0")

    if [[ "$cve_count" -eq 0 ]]; then
        echo "  No CVEs found" >&2
        return 0
    fi

    echo "  Found $cve_count CVEs" >&2

    local -a cve_records
    while IFS='|' read -r cve_id severity package description; do
        cve_records+=("${cve_id}|${severity}|${package}|${image_ref}|${description}")
    done < <(echo "$response" | jq -r '.data[] | "\(.cve_id)|\(.severity)|\(.affected_packages[0].name // "unknown")|\(.description // "No description")"' 2>/dev/null || echo "")

    if [[ ${#cve_records[@]} -gt 0 ]]; then
        VULNS+=("${cve_records[@]}")
    fi
}

query_api() {
    echo -e "${BOLD}${BLUE}=== Querying Red Hat Pyxis API ===${NC}" >&2

    for image in "${RELEVANT_IMAGES[@]}"; do
        local result=""
        query_image_metadata "$image" "result"

        local image_id="${result%%|*}"

        if [[ -n "$image_id" && "$image_id" != "NON_REDHAT" && "$image_id" != "ERROR" && "$image_id" != "NOT_FOUND" ]]; then
            echo "  Image ID: ${image_id}" >&2
            query_vulnerabilities "$image" "$image_id"
        fi
    done

    echo -e "${BOLD}Total vulnerabilities collected: ${#VULNS[@]}${NC}" >&2
}

# --- Severity Counting ---
# Counts vulnerabilities by severity level. Returns counts as a string:
#   critical|high|medium|low|unknown
# Accepts either:
#   - A nameref to an array of full vuln strings (CVE_ID|severity|package|image_ref|description)
#   - A nameref to an array of severity strings only
count_vulns_by_severity() {
    local array_name="$1"
    local -a items
    eval 'items=("${'"$array_name"'[@]}")'
    local critical=0 high=0 medium=0 low=0 unknown=0

    for item in "${items[@]}"; do
        if [[ "$item" == *\|* ]]; then
            IFS='|' read -r _ severity _ _ _ <<< "$item"
        else
            severity="$item"
        fi

        case "$severity" in
            Critical|CRITICAL)
                critical=$((critical + 1))
                ;;
            High|HIGH|Important|IMPORTANT)
                high=$((high + 1))
                ;;
            Medium|MEDIUM|Moderate|MODERATE)
                medium=$((medium + 1))
                ;;
            Low|LOW)
                low=$((low + 1))
                ;;
            *)
                unknown=$((unknown + 1))
                ;;
        esac
    done

    echo "${critical}|${high}|${medium}|${low}|${unknown}"
}

# --- Vulnerability Analysis ---
analyze_vulnerabilities() {
    echo -e "${BOLD}${BLUE}=== Analyzing Vulnerabilities ===${NC}" >&2

    local -a filtered_vulns

    for vuln in "${VULNS[@]}"; do
        # Filter by severity based on --show-all flag
        if [[ "$SHOW_ALL" == "true" ]]; then
            # Include all severities
            filtered_vulns+=("$vuln")
        else
            # Only include Critical and High (including Red Hat's "Important")
            IFS='|' read -r _ severity _ _ _ <<< "$vuln"
            if [[ "$severity" =~ ^(Critical|CRITICAL|High|HIGH|Important|IMPORTANT)$ ]]; then
                filtered_vulns+=("$vuln")
            fi
        fi
    done

    # Replace VULNS with filtered list (guard against empty array under set -u)
    if [[ ${#filtered_vulns[@]} -gt 0 ]]; then
        VULNS=("${filtered_vulns[@]}")
    else
        VULNS=()
    fi

    # Count severity on the *filtered* list so counts match the displayed CVEs
    local critical_count=0 high_count=0 medium_count=0 low_count=0 unknown_count=0
    if [[ ${#VULNS[@]} -gt 0 ]]; then
        local counts
        counts=$(count_vulns_by_severity VULNS)
        IFS='|' read -r critical_count high_count medium_count low_count unknown_count <<< "$counts"
    fi

    echo -e "  ${RED}${BOLD}Critical:${NC} $critical_count" >&2
    echo -e "  ${YELLOW}${BOLD}High:${NC} $high_count" >&2
    echo -e "  ${DIM}Medium: $medium_count $(if [[ "$SHOW_ALL" == "false" ]]; then echo "(hidden, use --show-all)"; fi)${NC}" >&2
    echo -e "  ${DIM}Low: $low_count $(if [[ "$SHOW_ALL" == "false" ]]; then echo "(hidden, use --show-all)"; fi)${NC}" >&2
    if [[ $unknown_count -gt 0 ]]; then
        echo -e "  Unknown: $unknown_count" >&2
    fi
    echo -e "${BOLD}  Showing: ${#VULNS[@]} CVEs${NC}" >&2
}

# --- Tag Analysis for Finding Fixes ---
# Red Hat images use pinned tags like "1-1781041605" or "9.8-1781010268".
# Floating tags ("1", "9.8", "latest") point at a pinned build but should not be suggested.
is_pinned_rh_tag() {
    [[ "$1" =~ ^[0-9]+(\.[0-9]+)*-[0-9]+$ ]]
}

get_tag_stream() {
    local tag="$1"
    if is_pinned_rh_tag "$tag"; then
        echo "${tag%-*}"
    elif [[ "$tag" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
        echo "$tag"
    else
        echo ""
    fi
}

get_tag_build_ts() {
    local tag="$1"
    if is_pinned_rh_tag "$tag"; then
        echo "${tag##*-}"
    else
        echo "0"
    fi
}

# --- Fetch Candidate Tags ---
# Queries the images API and returns candidate pinned tags (newer than current).
# Output: newline-separated "image_id|tag_name|build_ts" lines.
fetch_candidate_tags() {
    local image_ref="$1"

    # Parse image reference
    local parsed
    parsed=$(parse_image_reference "$image_ref")
    IFS='|' read -r registry repo current_tag <<< "$parsed"

    # Query recent images for this registry/repo
    local repo_encoded
    repo_encoded=$(printf '%s' "$repo" | jq -sRr @uri)
    local api_url="https://catalog.redhat.com/api/containers/v1/repositories/registry/${registry}/repository/${repo_encoded}/images"
    api_url+="?page_size=30"  # Limit to recent images for performance

    local response
    rate_limit_sleep
    response=$(rh_curl "$api_url" 2>&1)
    local curl_exit=$?

    if [[ $curl_exit -ne 0 ]]; then
        return 1
    fi

    local current_stream
    current_stream=$(get_tag_stream "$current_tag")
    local current_build_ts
    current_build_ts=$(get_tag_build_ts "$current_tag")

    # Resolve floating "latest" to the pinned tag on the same image
    if [[ -z "$current_stream" && "$current_tag" == "latest" ]]; then
        while IFS='|' read -r img_id tag_name; do
            if is_pinned_rh_tag "$tag_name"; then
                local ts
                ts=$(get_tag_build_ts "$tag_name")
                if [[ $ts -gt $current_build_ts ]]; then
                    current_stream=$(get_tag_stream "$tag_name")
                    current_build_ts="$ts"
                fi
            fi
        done < <(echo "$response" | jq -r '
            .data[]
            | select(.repositories[0].tags | map(.name) | index("latest"))
            | ._id as $img
            | .repositories[0].tags[]?
            | "\($img)|\(.name)"' 2>/dev/null)
    fi

    # Collect pinned tags (e.g. "1-1781041605", "9.8-1781010268"), newest builds first
    # Use process substitution instead of pipe to avoid subshell variable loss for current_stream/current_build_ts
    while IFS='|' read -r img_id tag_name build_ts; do
        [[ "$tag_name" == "$current_tag" ]] && continue
        [[ -z "$img_id" || -z "$tag_name" ]] && continue

        local stream
        stream=$(get_tag_stream "$tag_name")
        if [[ -n "$current_stream" && "$stream" != "$current_stream" ]]; then
            continue
        fi
        if [[ $build_ts -le $current_build_ts ]]; then
            continue
        fi

        echo "${img_id}|${tag_name}|${build_ts}"
    done < <(echo "$response" | jq -r '
        .data[]
        | select(.repositories[0].tags | length > 0)
        | ._id as $img
        | .repositories[0].tags[]?
        | select(.name | test("^[0-9]+(\\.[0-9]+)*-[0-9]+$"))
        | "\($img)|\(.name)|\(.name | split("-") | last)"' 2>/dev/null \
        | sort -t'|' -k3 -nr \
        | awk -F'|' '!seen[$1]++')
}

# --- Analyze Candidate for CVEs ---
# Given a candidate tag (image_id|tag_name|build_ts) and current CVEs as CSV,
# queries its vulnerabilities, counts fixes, and returns:
#   tag|build_ts|fixes_count|cand_critical|cand_high|fixed_cves_csv|remaining_cves_csv
analyze_candidate_for_cves() {
    local candidate="$1"
    local current_cves_csv="$2"

    IFS='|' read -r cand_image_id cand_tag cand_ts <<< "$candidate"

    # Query vulnerabilities for this candidate
    local vuln_response
    local curl_exit
    rate_limit_sleep
    vuln_response=$(rh_curl "https://catalog.redhat.com/api/containers/v1/images/id/${cand_image_id}/vulnerabilities" 2>&1)
    curl_exit=$?

    if [[ $curl_exit -ne 0 ]]; then
        return 1
    fi

    if ! echo "$vuln_response" | jq -e '.data | type == "array"' > /dev/null 2>&1; then
        echo "Warning: Unexpected API response shape for ${cand_tag}, skipping" >&2
        return 1
    fi

    local -a cand_severities=()
    while IFS='|' read -r severity; do
        [[ -n "$severity" ]] && cand_severities+=("$severity")
    done < <(echo "$vuln_response" | jq -r '.data[]? | .severity // empty' 2>/dev/null)

    local cand_critical=0 cand_high=0
    if [[ ${#cand_severities[@]} -gt 0 ]]; then
        local cand_counts
        cand_counts=$(count_vulns_by_severity cand_severities)
        IFS='|' read -r cand_critical cand_high _ _ _ <<< "$cand_counts"
    fi

    # Build set of CVEs in candidate
    local -A candidate_cves
    while read -r cve_id; do
        [[ -n "$cve_id" ]] && candidate_cves["$cve_id"]=1
    done < <(echo "$vuln_response" | jq -r '.data[]?.cve_id // empty' 2>/dev/null)

    # Count fixes by comparing candidate CVEs against current CVEs (CSV)
    local fixed_count=0
    local -a fixed_list=()
    local -a remaining_list=()

    IFS=',' read -ra current_cve_array <<< "$current_cves_csv"
    for cve in "${current_cve_array[@]}"; do
        # Trim leading/trailing whitespace
        cve="${cve#"${cve%%[![:space:]]*}"}"
        cve="${cve%"${cve##*[![:space:]]}"}"
        if [[ -z "${candidate_cves[$cve]:-}" ]]; then
            fixed_count=$((fixed_count + 1))
            fixed_list+=("$cve")
        else
            remaining_list+=("$cve")
        fi
    done

    # Return results: tag|build_ts|fixes_count|cand_critical|cand_high|fixed_cves_csv|remaining_cves_csv
    local fixed_str="" remaining_str=""
    if [[ ${#fixed_list[@]} -gt 0 ]]; then
        fixed_str=$(IFS=','; echo "${fixed_list[*]}")
    fi
    if [[ ${#remaining_list[@]} -gt 0 ]]; then
        remaining_str=$(IFS=','; echo "${remaining_list[*]}")
    fi
    echo "${cand_tag}|${cand_ts}|${fixed_count}|${cand_critical}|${cand_high}|${fixed_str}|${remaining_str}"
}

# --- Select Best Tag ---
# Compares candidates by fixes count then build timestamp.
# Returns: tag|fixes_count|fixed_cves|remaining_cves|new_critical|new_high
select_best_tag() {
    local -a candidates=("$@")

    if [[ ${#candidates[@]} -eq 0 ]]; then
        return 1
    fi

    local best_tag=""
    local max_fixes=0
    local best_build_ts=0
    local best_critical=0
    local best_high=0
    local -a best_fixed_cves=()
    local -a best_remaining_cves=()

    for candidate in "${candidates[@]}"; do
        IFS='|' read -r cand_tag cand_build_ts cand_fixes cand_critical cand_high cand_fixed_cves cand_remaining_cves <<< "$candidate"

        # Prefer more fixes, then newer build timestamp
        if [[ $cand_fixes -gt $max_fixes ]] || { [[ $cand_fixes -eq $max_fixes ]] && [[ $cand_build_ts -gt $best_build_ts ]]; }; then
            max_fixes=$cand_fixes
            best_tag="$cand_tag"
            best_build_ts="$cand_build_ts"
            best_critical="$cand_critical"
            best_high="$cand_high"
            best_fixed_cves=()
            best_remaining_cves=()
            if [[ -n "$cand_fixed_cves" ]]; then
                IFS=',' read -ra best_fixed_cves <<< "$cand_fixed_cves"
            fi
            if [[ -n "$cand_remaining_cves" ]]; then
                IFS=',' read -ra best_remaining_cves <<< "$cand_remaining_cves"
            fi
        fi

    done

    # Return results: tag|fixes_count|fixed_cves|remaining_cves|new_critical|new_high
    if [[ -n "$best_tag" && $max_fixes -gt 0 ]]; then
        local fixed_str="" remaining_str=""
        if [[ ${#best_fixed_cves[@]} -gt 0 ]]; then
            fixed_str=$(IFS=','; echo "${best_fixed_cves[*]}")
        fi
        if [[ ${#best_remaining_cves[@]} -gt 0 ]]; then
            remaining_str=$(IFS=','; echo "${best_remaining_cves[*]}")
        fi
        echo "${best_tag}|${max_fixes}|${fixed_str}|${remaining_str}|${best_critical}|${best_high}"
        return 0
    fi

    return 1
}

# --- Find Best Upgrade Tag (orchestrator) ---
find_best_upgrade_tag() {
    local image_ref="$1"
    local current_cves_csv="$2"  # comma-separated list of current CVEs

    local parsed
    parsed=$(parse_image_reference "$image_ref")
    IFS='|' read -r registry repo current_tag <<< "$parsed"

    echo "  Finding best upgrade tag for ${registry}/${repo}..." >&2

    # Fetch candidate tags (pinned tags newer than current)
    local -a candidate_tags=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && candidate_tags+=("$line")
    done < <(fetch_candidate_tags "$image_ref")

    if [[ ${#candidate_tags[@]} -eq 0 ]]; then
        echo ""
        return 1
    fi

    echo "    Analyzing ${#candidate_tags[@]} candidate pinned tags..." >&2

    # Analyze each candidate for CVE fixes (newest builds first)
    local -a analysis_results
    for candidate in "${candidate_tags[@]}"; do
        local result
        result=$(analyze_candidate_for_cves "$candidate" "$current_cves_csv")
        if [[ -n "$result" ]]; then
            analysis_results+=("$result")
            local remaining
            remaining=$(echo "$result" | cut -d'|' -f7)
            if [[ -z "$remaining" ]]; then
                break
            fi
        fi
    done

    if [[ ${#analysis_results[@]} -eq 0 ]]; then
        echo ""
        return 1
    fi

    # Select the best tag from analysis results
    select_best_tag "${analysis_results[@]}"
}

# --- Group CVEs by Image ---
# Groups CVEs by image reference and returns:
#   image_ref|cve1,cve2,...|critical_count,high_count
group_cves_by_image() {
    local -A image_cves
    local -A image_cve_details

    for vuln in "${VULNS[@]}"; do
        IFS='|' read -r cve_id severity package image_ref description <<< "$vuln"

        if [[ -z "${image_cves[$image_ref]:-}" ]]; then
            image_cves["$image_ref"]="$cve_id"
        else
            image_cves["$image_ref"]+=", $cve_id"
        fi

        image_cve_details["${image_ref}|${cve_id}"]="$severity"
    done

    for image_ref in "${!image_cves[@]}"; do
        local cves="${image_cves[$image_ref]}"

        # Build associative array of current CVEs for this image
        local -A current_cves
        IFS=',' read -ra cve_array <<< "$cves"
        for cve in "${cve_array[@]}"; do
            # Trim leading/trailing whitespace
            cve="${cve#"${cve%%[![:space:]]*}"}"
            cve="${cve%"${cve##*[![:space:]]}"}"
            current_cves["$cve"]=1
        done

        # Count current CVEs by severity
        local -a image_cve_sevs=()
        for cve in "${!current_cves[@]}"; do
            local sev="${image_cve_details[${image_ref}|${cve}]:-}"
            image_cve_sevs+=("$sev")
        done

        local current_critical=0 current_high=0
        if [[ ${#image_cve_sevs[@]} -gt 0 ]]; then
            local image_counts
            image_counts=$(count_vulns_by_severity image_cve_sevs)
            IFS='|' read -r current_critical current_high _ _ _ <<< "$image_counts"
        fi

        # Build comma-separated list of current CVEs for this image
        local current_cves_csv=""
        if [[ ${#current_cves[@]} -gt 0 ]]; then
            current_cves_csv=$(IFS=','; echo "${!current_cves[*]}")
        fi

        # Return: image_ref|cves_csv|critical_count|high_count|current_cves_csv
        echo "${image_ref}|${cves}|${current_critical}|${current_high}|${current_cves_csv}"
    done
}

# --- Build Catalog URL ---
# Given a Red Hat image reference, builds the catalog URL.
build_catalog_url() {
    local image_ref="$1"

    local cached_value="${IMAGE_CACHE[$image_ref]:-}"
    local catalog_url="https://catalog.redhat.com/"

    if [[ "$cached_value" == *:* ]]; then
        local repo_id="${cached_value##*:}"
        local repo_path="${image_ref#*/}"
        repo_path="${repo_path%:*}"
        catalog_url="https://catalog.redhat.com/software/containers/${repo_path}/${repo_id}"
    fi

    echo "$catalog_url"
}

# --- Format Remediation for Image ---
# Formats remediation text for a single image, including upgrade suggestions.
format_remediation_for_image() {
    local image_ref="$1"
    local cves_csv="$2"
    local current_critical="$3"
    local current_high="$4"
    local current_cves_csv="$5"

    # For Red Hat images, provide catalog link
    if [[ "$image_ref" =~ registry\.access\.redhat\.com ]]; then
        # Extract current tag
        local current_tag=""
        if [[ "$image_ref" =~ :([^:]+)$ ]]; then
            current_tag="${BASH_REMATCH[1]}"
        fi

        # Build remediation (plain terminal text)
        local remediation=""
        remediation+="Image: ${image_ref}\n"
        remediation+="  Current tag      : ${current_tag}\n"
        remediation+="  Vulnerabilities  : ${current_critical} Critical, ${current_high} Important\n"
        remediation+="  Affected CVEs    : ${cves_csv}\n"

        # Try to find a better tag by analyzing candidates
        local line_num="${IMAGE_LINES[$image_ref]:-unknown}"
        local dockerfile_name="$(basename "${DOCKERFILE_PATH}")"

        local upgrade_info
        upgrade_info=$(find_best_upgrade_tag "$image_ref" "$current_cves_csv")

        if [[ -n "$upgrade_info" ]]; then
            IFS='|' read -r best_tag fixes_count remaining_cves new_critical new_high <<< "$upgrade_info"

            # Extract registry/repo from image_ref (already have current_tag from L865-866)
            local registry="" repo=""
            if [[ "$image_ref" =~ ^([^/]+)/([^:]+) ]]; then
                registry="${BASH_REMATCH[1]}"
                repo="${BASH_REMATCH[2]%:*}"
            fi

            local new_image_ref="${registry}/${repo}:${best_tag}"
            PATCH_ENTRIES+=("${line_num}|${image_ref}|${new_image_ref}")

            remediation+="\n"
            remediation+="  Suggested change (${dockerfile_name}, line ${line_num}):\n"
            remediation+="    ${RED}- FROM ${image_ref}${NC}\n"
            remediation+="    ${GREEN}+ FROM ${new_image_ref}${NC}\n"
            remediation+="\n"
            remediation+="  Upgraded image   : ${new_critical:-0} Critical, ${new_high:-0} Important CVEs\n"
            local unique_cves_without_commas="${current_cves_csv//,/}"
            local total_unique_cves=$(( ${#current_cves_csv} - ${#unique_cves_without_commas} + 1 ))
            (( total_unique_cves > 0 )) || total_unique_cves=0
            remediation+="  Fixes            : ${fixes_count}/${total_unique_cves} reported CVEs"
            if [[ -z "$remaining_cves" ]]; then
                remediation+=" (all resolved)"
            fi
            remediation+="\n"

            if [[ -n "$remaining_cves" ]]; then
                local remaining_without_commas="${remaining_cves//,/}"
                local remaining_count=$(( ${#remaining_cves} - ${#remaining_without_commas} + 1 ))
                remediation+="  Note             : ${remaining_count} reported CVE(s) remain (may be backport-patched)\n"
            fi

            # Get catalog URL
            local catalog_url
            catalog_url=$(build_catalog_url "$image_ref")
            remediation+="  Catalog          : ${catalog_url}\n"
        else
            remediation+="\n"
            remediation+="  No upgrade found (${dockerfile_name}, line ${line_num})\n"
            remediation+="  Analyzed available tags but none fix the reported CVEs.\n"
            remediation+="  CVEs may be backport-patched, awaiting a future release, or false positives.\n"
        fi

        # Strip color codes when output is not a terminal
        echo -e "$remediation"
    else
        # Non-Red Hat images
        local remediation=""
        remediation+="Image: ${image_ref}\n"
        remediation+="  Affected CVEs    : ${cves_csv}\n"
        remediation+="  Recommendation   : Check upstream registry for security updates\n"

        echo -e "$remediation"
    fi
}

# --- Remediation Generation ---
generate_remediation() {
    echo -e "${BOLD}${BLUE}=== Generating Remediation ===${NC}" >&2

    # Skip if no vulnerabilities to remediate
    if [[ ${#VULNS[@]} -eq 0 ]]; then
        echo "No vulnerabilities to remediate" >&2
        return 0
    fi

    # Group CVEs by image and generate remediation for each
    local group_result
    group_result=$(group_cves_by_image)
    if [[ -z "$group_result" ]]; then
        echo "No CVEs to remediate" >&2
        return 0
    fi

    while IFS='|' read -r image_ref cves_csv current_critical current_high current_cves_csv; do
        local remediation
        remediation=$(format_remediation_for_image "$image_ref" "$cves_csv" "$current_critical" "$current_high" "$current_cves_csv")

        if [[ -n "$remediation" ]]; then
            REMEDIATIONS+=("$remediation")
        fi
    done <<< "$group_result"

    echo -e "${GREEN}Generated ${#REMEDIATIONS[@]} remediation suggestions${NC}" >&2
}

# --- Report Generation ---

# Formats the summary section (header + severity counts)
format_summary() {
    print_ruler 78
    echo -e "${BOLD} Dockerfile Vulnerability Report${NC}"
    print_ruler 78
    echo ""
    print_kv "Generated" "$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    print_kv "Dockerfile" "${DOCKERFILE_PATH}"

    # Summary section
    print_section "SUMMARY"

    local critical_count=0 high_count=0 medium_count=0 low_count=0
    if [[ ${#VULNS[@]} -gt 0 ]]; then
        local counts
        counts=$(count_vulns_by_severity VULNS)
        IFS='|' read -r critical_count high_count medium_count low_count _ <<< "$counts"
    fi

    echo -e "  ${RED}${BOLD}Critical${NC}  : $critical_count"
    echo -e "  ${YELLOW}${BOLD}High${NC}      : $high_count"
    if [[ "$SHOW_ALL" == "true" ]]; then
        echo -e "  ${DIM}Medium${NC}    : $medium_count"
        echo -e "  ${DIM}Low${NC}       : $low_count"
    else
        echo -e "  ${DIM}Medium${NC}    : (hidden, use --show-all)"
        echo -e "  ${DIM}Low${NC}       : (hidden, use --show-all)"
    fi
    echo -e "  ${BOLD}Showing${NC}   : ${#VULNS[@]} CVE(s)"
}

# Formats the vulnerability table section
format_vulnerability_table() {
    if [[ ${#VULNS[@]} -gt 0 ]]; then
        print_section "VULNERABILITIES"

        printf "  %-20s %-12s %-14s %-24s %s\n" "CVE" "Severity" "Package" "Image" "Description"
        print_ruler 78

        for vuln in "${VULNS[@]}"; do
            IFS='|' read -r cve_id severity package image_ref description <<< "$vuln"
            local short_desc="${description:0:50}"
            if [[ ${#description} -gt 50 ]]; then
                short_desc="${short_desc}..."
            fi
            local short_image="${image_ref##*/}"

            printf "  %-20s %-12s %-14s %-24s %s\n" \
                "$cve_id" "$severity" "$package" "$short_image" "$short_desc"
        done
    else
        print_section "VULNERABILITIES"
        echo "  No vulnerabilities found (or all filtered by severity threshold)."
    fi
}

# Formats the remediation section
format_remediation_section() {
    if [[ ${#REMEDIATIONS[@]} -gt 0 ]]; then
        print_section "SUGGESTED IMAGE UPGRADES"
        local first=true
        for remediation in "${REMEDIATIONS[@]}"; do
            if [[ "$first" == "false" ]]; then
                echo ""
                print_ruler 78
                echo ""
            fi
            first=false
            echo -e "$remediation"
        done
    fi
}

generate_report() {
    format_summary
    format_vulnerability_table
    format_remediation_section

    # Footer
    echo ""
    print_ruler 78
}

# --- Patch Generation ---
generate_patch() {
    local patch_file="${DOCKERFILE_PATH}.patch"
    local dockerfile_basename
    dockerfile_basename="$(basename "$DOCKERFILE_PATH")"

    {
        echo "--- a/${dockerfile_basename}"
        echo "+++ b/${dockerfile_basename}"
        echo "@@ ... @@"

        printf '%s\n' "${PATCH_ENTRIES[@]}" | sort -t'|' -k1 -n | while IFS='|' read -r line_num _ new_ref; do
            sed -n "${line_num}p" "$DOCKERFILE_PATH" | while read -r original_line; do
                echo "-${original_line}"
                echo "+FROM ${new_ref}"
            done
        done
    } > "$patch_file"

    echo -e "${GREEN}Patch written to: ${patch_file}${NC}" >&2
    echo -e "${YELLOW}Apply with: patch -p0 < ${patch_file}${NC}" >&2
}

# --- Main Entry Point ---
main() {
    check_dependencies
    parse_args "$@"

    # Validate required arguments
    if [[ -z "$DOCKERFILE_PATH" ]]; then
        echo "Error: Dockerfile path is required" >&2
        echo "" >&2
        show_help
        exit 1
    fi

    parse_dockerfile "$DOCKERFILE_PATH"
    trace_from_dependencies
    query_api
    analyze_vulnerabilities
    generate_remediation
    generate_report
    if [[ "$PATCH_MODE" == "true" ]]; then
        generate_patch
    fi
}

# Run main if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
