# Sourced by scripts/container after engine selection and private-temp setup.
# Only inert image archives are mounted; never expose an engine or SSH socket.
[[ $# == 0 ]] || fail 'Usage: make osv-scan (no extra scanner arguments).'
[[ $project_root != *,* && $project_root != *$'\n'* ]] || fail 'Project paths must contain no commas or newlines.'
mkdir -p "$project_root/.container/osv"
report_dir=$(mktemp -d "$project_root/.container/osv/run.XXXXXXXX")
osv_exit=0
osv_args=(run --rm --read-only --user "$host_uid:$host_gid" --cap-drop=ALL
    --security-opt=no-new-privileges --pids-limit=256 --memory=2g
    --tmpfs /tmp:rw,nosuid,nodev,size=2g --workdir /workspace)
if [[ $engine_version == *[Pp]odman* ]]; then osv_args+=(--userns=keep-id); fi

osv_build() {
    local stage=$1
    "$engine" build --target "$stage" --build-arg "WG_UID=$host_uid" --build-arg "WG_GID=$host_gid" \
        --iidfile "$build_dir/$stage.id" --file Dockerfile "$project_root" >&2
    built_id=$(cat "$build_dir/$stage.id")
    [[ $built_id =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'OSV target build did not produce an immutable image ID.'
    printf '%s\t%s\n' "$stage" "$built_id" >> "$report_dir/images.tsv"
}

osv_scan() {
    local label=$1 kind=$2 scan_status=0
    local mounts=()
    local scan_options=(source --no-resolve --no-call-analysis=go
        --lockfile=requirements.txt:/workspace/locks/requirements.lock
        --lockfile=requirements.txt:/workspace/locks/requirements-dev.lock)
    if [[ $kind == image ]]; then
        mounts=(--mount "type=bind,src=$build_dir/image.tar,dst=/artifacts/image.tar,readonly")
        scan_options=(image --archive /artifacts/image.tar)
    elif [[ $kind == recursive ]]; then
        # Exercise the same discovery/resolution defaults as `osv-scanner -r .`.
        scan_options=(source --recursive /workspace)
    fi
    if "$engine" "${osv_args[@]}" "${mounts[@]}" "$scanner_id" scan "${scan_options[@]}" \
        --format=json --all-packages > "$report_dir/$label.json" 2> "$report_dir/$label.log"; then
        scan_status=0
    else
        scan_status=$?
    fi
    printf '%s\t%s\n' "$label" "$scan_status" >> "$report_dir/status.tsv"
    printf '\nOSV: %s (scanner exit %s)\n' "$label" "$scan_status"
    if [[ $scan_status != 0 && $scan_status != 1 ]]; then
        printf 'Scan incomplete; see %s/%s.log\n' "$report_dir" "$label" >&2
        osv_exit=2
        return
    fi
    if [[ $scan_status == 1 && $osv_exit == 0 ]]; then osv_exit=1; fi
    if ! "$engine" "${osv_args[@]}" --network=none --entrypoint python \
        --mount "type=bind,src=$report_dir/$label.json,dst=/artifacts/report.json,readonly" \
        "$scanner_id" scripts/osv_report.py /artifacts/report.json; then
        osv_exit=2
    fi
}

printf 'OSV reports: %s\n' "$report_dir"
osv_build osv-tools
scanner_id=$built_id
osv_scan locks source
osv_scan requirements recursive
for scan_target in runtime dev dnsfilter-runtime; do
    osv_build "$scan_target"
    if [[ $engine_version == *[Pp]odman* ]]; then
        "$engine" save --format=docker-archive --output "$build_dir/image.tar" "$built_id" >&2
    else
        "$engine" save --output "$build_dir/image.tar" "$built_id" >&2
    fi
    osv_scan "$scan_target" image
    rm -- "$build_dir/image.tar"
done
printf '\nReports retained in %s\n' "$report_dir"
printf 'Exit 0: no active findings; 1: findings remain; 2: incomplete scan. No project ignore rules are applied.\n'
