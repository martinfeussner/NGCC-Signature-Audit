#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 /path/to/ngcc-harness/sign-25" >&2
    exit 2
fi

sign25_dir=$(cd "$1" && pwd)
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
build_dir="$script_dir/build"
bin_dir="$build_dir/bin"
results_file="$build_dir/reproduction.txt"
cc_bin=${CC:-cc}
jobs=${JOBS:-1}

if [[ ! -f "$sign25_dir/Makefile" || ! -d "$sign25_dir/Implementations/Reference_Implementation" ]]; then
    echo "The argument is not an ngcc-harness sign-25 directory." >&2
    exit 2
fi

instances=(
    SQISign2Dsquare-Level1-eff_compressed
    SQISign2Dsquare-Level1-sec_compressed
    SQISign2Dsquare-Level2-eff_compressed
    SQISign2Dsquare-Level2-sec_compressed
    SQISign2Dsquare-Level3-eff_compressed
    SQISign2Dsquare-Level3-sec_compressed
    SQISign2Dsquare-Level5-eff_compressed
    SQISign2Dsquare-Level5-sec_compressed
)
labels=(
    Level1-eff Level1-sec Level2-eff Level2-sec
    Level3-eff Level3-sec Level5-eff Level5-sec
)

mkdir -p "$bin_dir"

# Prefer a normal GMP development installation.  The NGCC archive also ships a
# Windows-configured gmp.h; the fallback below makes that header usable with a
# versioned Linux GMP runtime when the development package is absent.
gmp_compile_flags=()
gmp_link_flags=(-lgmp)
make_cc=$cc_bin
if ! printf '#include <gmp.h>\n' | "$cc_bin" -x c -E - >/dev/null 2>&1; then
    gmp_include="$sign25_dir/Implementations/Reference_Implementation/SQISign2Dsquare-Level1-eff/gmp"
    if [[ ! -f "$gmp_include/gmp.h" ]]; then
        echo "No system gmp.h and no submission fallback header were found." >&2
        exit 3
    fi

    gmp_runtime=""
    if command -v ldconfig >/dev/null 2>&1; then
        gmp_runtime=$(ldconfig -p 2>/dev/null | awk '/libgmp\.so\.[0-9]+ .*=>/ {print $NF; exit}')
    fi
    if [[ -z "$gmp_runtime" ]]; then
        for candidate in /lib/x86_64-linux-gnu/libgmp.so.* /usr/lib/x86_64-linux-gnu/libgmp.so.*; do
            if [[ -f "$candidate" ]]; then
                gmp_runtime=$candidate
                break
            fi
        done
    fi
    if [[ -z "$gmp_runtime" ]]; then
        echo "A GMP development package or versioned GMP runtime is required." >&2
        exit 3
    fi

    compat_dir="$build_dir/gmp-compat"
    mkdir -p "$compat_dir"
    ln -sfn "$gmp_runtime" "$compat_dir/libgmp.so"
    export CPATH="$gmp_include${CPATH:+:$CPATH}"
    export LIBRARY_PATH="$compat_dir${LIBRARY_PATH:+:$LIBRARY_PATH}"
    make_cc="$cc_bin -D__GMP_WITHIN_CONFIGURE"
    gmp_compile_flags=(-I"$gmp_include" -D__GMP_WITHIN_CONFIGURE)
    gmp_link_flags=(-L"$compat_dir" -lgmp)
fi

echo "Building the eight unmodified compact reference implementations..."
library_targets=()
for instance in "${instances[@]}"; do
    library_targets+=("lib/lib$instance.so")
done
make -C "$sign25_dir" -j "$jobs" "${library_targets[@]}" "CC=$make_cc"

: > "$results_file"
for i in "${!instances[@]}"; do
    instance=${instances[$i]}
    label=${labels[$i]}
    source_dir="$sign25_dir/src/$instance"
    object_dir="$sign25_dir/build/$instance"
    executable="$bin_dir/compact_retarget_$label"

    if [[ ! -d "$source_dir" || ! -d "$object_dir" ]]; then
        echo "Missing build output for $instance." >&2
        exit 4
    fi

    objects=()
    while IFS= read -r -d '' object; do
        objects+=("$object")
    done < <(find "$object_dir" -maxdepth 1 -type f -name '*.o' -print0 | sort -z)
    if [[ ${#objects[@]} -eq 0 ]]; then
        echo "No implementation objects found for $instance." >&2
        exit 4
    fi

    "$cc_bin" -O2 -std=gnu11 -DNDEBUG -DCOMPRESSED=1 \
        "-DATTACK_LABEL=\"$label\"" \
        -I"$source_dir" -I"$source_dir/sqisign" \
        -I"$source_dir/ec_arithmetic/include" \
        "${gmp_compile_flags[@]}" \
        "$script_dir/compact_retarget.c" "${objects[@]}" \
        -o "$executable" -lm "${gmp_link_flags[@]}"

    "$executable" | tee -a "$results_file"
done

pass_count=$(grep -c 'status=PASS' "$results_file" || true)
if [[ $pass_count -ne 8 ]]; then
    echo "Expected eight PASS lines, found $pass_count." >&2
    exit 5
fi

echo "All eight parameter sets passed. Results: $results_file"
