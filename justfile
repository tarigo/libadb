# Development tasks for libadb. Run `just` to list them.
#
# CI drives the same recipes, so a green `just ci` locally means the
# same commands, flags and feature sets the workflow will run — except
# for the jobs that need tooling beyond cargo and stay out of `ci`:
#
#   fuzzing     `just fuzz-all`   nightly + cargo-fuzz, a minute per target
#   coverage    `just coverage`   cargo-llvm-cov; measures, cannot go red
#   semver      `just semver`     cargo-semver-checks + crates.io baseline
#   C header    `just ffi-header` bindgen, needs libclang

# Feature sets. CI keeps its own matrix for parallelism; these are the
# lists a full local run walks.
lib_features := "tokio smol tokio,usb tokio,rusb tokio,smol tokio,nusb,rusb smol,usb smol,rusb"
ffi_features := "usb rusb nusb,rusb"
# Documentation is built per narrow combination: an intra-doc link to a
# type behind another feature only breaks when that feature is off.
doc_features := "tokio smol tokio,rusb smol,nusb tokio,smol,nusb,rusb"
msrv_version := "1.87.0"
no_std_target := "thumbv7m-none-eabi"
fuzz_targets := "packet_decode shell_v2_frames sync_parse"
# What the bottom of a stack sits on; see the `restack` and `mutants`
# recipes.
restack_base := "origin/main"
# Feature set mutants are hunted under. It has to cover the code being
# mutated: a mutant inside a `cfg`-ed out module compiles away, the
# tests pass, and it is reported as surviving when nothing was tested at
# all. Both runtimes and both USB backends cover the crate.
mutants_features := "tokio,smol,nusb,rusb"
# Seconds a single mutant may take before it counts as a timeout. A
# mutant that loops forever would otherwise hold the run open.
mutants_timeout := "120"
# Features coverage is measured under: what CI's tests exercise without
# hardware. The USB backends stay out on purpose — their tests need a
# device, so compiling them in would only grow the denominator with
# lines nothing on CI can reach.
coverage_features := "tokio,smol"

# The warning policy every recipe runs under, CI included: clippy takes
# `-D warnings` on its own command line, but rustc warnings from tests,
# MSRV checks and the no-std build only fail the build through this.
# Override for a one-off run: `just RUSTFLAGS='-D warnings -C …' ci`.
export RUSTFLAGS := "-D warnings"

default:
    @just --list

# Everything CI checks, except the extra-tooling recipes — see the
# table at the top.
ci: fmt-check clippy clippy-ffi test doc msrv no-std all-features

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

# --- single-configuration recipes: what CI's matrix jobs call ---------

clippy-one features:
    cargo clippy -p libadb --no-default-features --features "{{features}}" --all-targets -- -D warnings

clippy-ffi-one features="":
    cargo clippy -p libadb-ffi --no-default-features --features "{{features}}" --all-targets -- -D warnings

test-one features:
    cargo test -p libadb --no-default-features --features "{{features}}"

test-ffi-one features="":
    cargo test -p libadb-ffi --no-default-features --features "{{features}}"

# Line coverage of the workspace tests, as a terminal table. Needs
# cargo-llvm-cov (and the llvm-tools-preview rustup component).
coverage:
    cargo llvm-cov --workspace --no-default-features --features {{coverage_features}}

# The same run as JSON on stdout — the CI badge reads
# .data[0].totals.lines.percent out of it.
coverage-json:
    cargo llvm-cov --workspace --no-default-features --features {{coverage_features}} --json --summary-only

# Public-API semver conformance: every crate's API is compared against
# its released crates.io version, and changes must fit the version bump
# Cargo.toml carries (pre-1.0: breaking needs 0.x -> 0.x+1). Needs
# cargo-semver-checks (`cargo install cargo-semver-checks --locked`).
semver:
    cargo semver-checks --workspace --all-features

# The hand-written libadb.h against the Rust implementation: function
# signatures compare at compile time, enum values and layouts at run
# time. Needs libclang (bindgen).
ffi-header:
    cargo test -p header-check

doc-one package features:
    RUSTDOCFLAGS="-D warnings" cargo doc -p {{package}} --no-default-features --features "{{features}}" --no-deps

msrv-one package features="":
    cargo +{{msrv_version}} check -p {{package}} --no-default-features --features "{{features}}"

# --- full sweeps: what a local run walks ------------------------------

clippy:
    #!/usr/bin/env bash
    set -euo pipefail
    for f in {{lib_features}}; do
        echo "== clippy libadb [$f]"
        just clippy-one "$f"
    done

clippy-ffi:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "== clippy libadb-ffi [no features]"
    just clippy-ffi-one ""
    for f in {{ffi_features}}; do
        echo "== clippy libadb-ffi [$f]"
        just clippy-ffi-one "$f"
    done

test:
    #!/usr/bin/env bash
    set -euo pipefail
    for f in {{lib_features}}; do
        echo "== test [$f]"
        just test-one "$f"
    done
    echo "== test libadb-ffi [no features]"
    just test-ffi-one ""
    for f in {{ffi_features}}; do
        echo "== test libadb-ffi [$f]"
        just test-ffi-one "$f"
    done

doc:
    #!/usr/bin/env bash
    set -euo pipefail
    for f in {{doc_features}}; do
        echo "== doc libadb [$f]"
        just doc-one libadb "$f"
    done
    for f in {{ffi_features}}; do
        echo "== doc libadb-ffi [$f]"
        just doc-one libadb-ffi "$f"
    done

msrv:
    #!/usr/bin/env bash
    set -euo pipefail
    for f in tokio smol split tokio,rusb smol,nusb tokio,smol; do
        echo "== msrv libadb [$f]"
        just msrv-one libadb "$f"
    done
    just msrv-one libadb-ffi ""
    for f in {{ffi_features}}; do
        just msrv-one libadb-ffi "$f"
    done

# The no_std + alloc promise: build the core against a bare-metal
# target, on the MSRV toolchain as CI does. Installs toolchain and
# target if missing, so a fresh checkout can run this without a separate
# rustup step.
no-std target=no_std_target:
    rustup toolchain install {{msrv_version}} --profile minimal --target {{target}}
    cargo +{{msrv_version}} check -p libadb --target {{target}} --no-default-features

# Features must be additive: every combination has to compile.
all-features:
    cargo build -p libadb --all-features --all-targets

# --- things that are not plain cargo ----------------------------------

# Build the C example against the cdylib.
ffi-example:
    cargo build -p libadb-ffi
    cc -I libadb-ffi/include -o target/ffi_shell libadb-ffi/examples/ffi_shell.c \
        -L target/debug -ladb -lpthread -ldl -lm
    @echo "built target/ffi_shell"

# How a stack is moved after its bottom changed or merged:
#
#     just restack usb-additive runtime-trait rusb-runtime
#
# The first branch is rebased onto `restack_base` (override with
# `just --set restack_base other-branch restack …`) — a no-op if it is
# already there, and if it was squash-merged its commit drops out by
# patch-id. Every later branch moves from its parent's *previous* tip
# onto the new one, which keeps an amended parent from reappearing as a
# duplicate commit.
#
# Rebase a stack of branches bottom-up and force-push each.
restack +stack:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
        echo "working tree is dirty — commit or stash first" >&2
        exit 1
    fi
    git fetch --quiet origin
    started_on=$(git rev-parse --abbrev-ref HEAD)
    parent="{{restack_base}}"
    parent_old=""
    for branch in {{stack}}; do
        branch_old=$(git rev-parse "$branch")
        echo "== $branch onto $parent"
        if [ -z "$parent_old" ]; then
            git rebase "$parent" "$branch"
        else
            git rebase --onto "$parent" "$parent_old" "$branch"
        fi
        git push --force-with-lease origin "$branch"
        parent_old="$branch_old"
        parent="$branch"
    done
    git switch --quiet "$started_on"
    echo "stack re-based; GitHub retargets the PRs itself once the base branch is deleted on merge"

# Mutation testing: change the code in small ways and see whether the
# tests notice. Needs cargo-mutants (`cargo install cargo-mutants
# --locked`).
#
#     just mutants                                 # what this branch changed
#     just mutants libadb/src/base/destination.rs  # named files
#
# With no arguments it only looks at code this branch touched against
# `restack_base`, which keeps a run to minutes; naming files widens it
# deliberately. Surviving mutants are gaps in the tests, not build
# failures, so this is not part of `ci`. Mutants that no test could
# ever tell apart are listed in `.cargo/mutants.toml`.
#
# Hunt for code the tests do not actually pin down.
mutants *files:
    #!/usr/bin/env bash
    set -euo pipefail
    # `nproc` is GNU; macOS answers with sysctl and neither is
    # guaranteed, so fall back to a modest fixed number.
    jobs=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    common=(--package libadb --features "{{mutants_features}}" \
            --timeout {{mutants_timeout}} --jobs "$jobs")
    if [ -n "{{files}}" ]; then
        args=()
        for f in {{files}}; do args+=(--file "$f"); done
        exec cargo mutants "${common[@]}" "${args[@]}"
    fi
    diff=$(mktemp)
    trap 'rm -f "$diff"' EXIT
    git diff --merge-base "{{restack_base}}" -- '*.rs' > "$diff"
    if [ ! -s "$diff" ]; then
        echo "no Rust changes against {{restack_base}} — name files to widen the hunt" >&2
        exit 0
    fi
    cargo mutants "${common[@]}" --in-diff "$diff"

# Fuzz one target for `seconds` (needs nightly and cargo-fuzz).
#
# The target triple is passed explicitly: a cargo-fuzz binary that was
# itself built for musl otherwise picks musl for the build too, where
# there is no prebuilt std.
fuzz target seconds="60":
    #!/usr/bin/env bash
    set -euo pipefail
    host=$(rustc +nightly -vV | awk '/^host:/{print $2}')
    cargo +nightly fuzz run --fuzz-dir fuzz --target "$host" {{target}} \
        -- -max_total_time={{seconds}}

# Every fuzz target, briefly — what CI runs on each push.
fuzz-all seconds="60":
    #!/usr/bin/env bash
    set -euo pipefail
    for t in {{fuzz_targets}}; do
        echo "== fuzz $t"
        just fuzz "$t" "{{seconds}}"
    done
