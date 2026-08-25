# Development tasks for libadb. Run `just` to list them.
#
# CI drives the same recipes, so a green `just ci` locally means the
# same commands, flags and feature sets the workflow will run.

# Feature sets. CI keeps its own matrix for parallelism; these are the
# lists a full local run walks.
lib_features := "tokio smol tokio,usb tokio,rusb tokio,smol tokio,nusb,rusb smol,usb smol,rusb"
ffi_features := "usb rusb nusb,rusb"
# Documentation is built per narrow combination: an intra-doc link to a
# type behind another feature only breaks when that feature is off.
doc_features := "tokio smol tokio,rusb smol,nusb tokio,smol,nusb,rusb"
msrv_version := "1.87.0"
no_std_target := "thumbv7m-none-eabi"
# What the bottom of a stack sits on; see the `restack` recipe.
restack_base := "origin/main"

# The warning policy every recipe runs under, CI included: clippy takes
# `-D warnings` on its own command line, but rustc warnings from tests,
# MSRV checks and the no-std build only fail the build through this.
# Override for a one-off run: `just RUSTFLAGS='-D warnings -C …' ci`.
export RUSTFLAGS := "-D warnings"

default:
    @just --list

# Everything CI checks.
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

# Fuzz one target for `seconds` (needs nightly and cargo-fuzz).
fuzz target seconds="60":
    cargo +nightly fuzz run --fuzz-dir fuzz {{target}} -- -max_total_time={{seconds}}
