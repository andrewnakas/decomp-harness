# Runbook: a new Skate 3 subsystem

What follows is the real sequence, with the numbers this machine produced.

## Once

```sh
uv tool install --editable ~/Documents/DecompHarness --python 3.13 \
    --with pyghidra --with mcp

decomp init ~/Documents/skate3-decomp --target xex --name skate3 \
    --recomp ~/skate3/skate3recomp-dev
cd ~/Documents/skate3-decomp
decomp doctor
```

`doctor` checks the toolchain and runs the lessons' guards. Ghidra needs a JDK
21 or newer; Python must be 3.13 or older, because that is as far as the bundled
PyGhidra wheels go.

## Ingest what is already known

```sh
decomp import lifted ~/skate3/skate3recomp-dev/generated
decomp import names  ~/Documents/sk8AudioDecompile/out/names.csv --kind plugin_meta
decomp import structs ~/Documents/sk8AudioDecompile/docs/rw_audio_structs.h
decomp import decomp ~/Documents/sk8AudioDecompile/out/decomp
decomp import queue  <phase0-measurements>/probe/ports/queue.json
decomp import trace  <a guest trace>  --profile play
```

Observed here:

| Step | Result |
|---|---|
| lifted | 47,652 functions, 21,707 resolved names, 294 helper and import symbols |
| names | 421 |
| structs | 9 structs, 51 fields, every offset cited to the function it came from |
| decomp | 1,694 registered, 52 the decompiler could not recover |

The queue and trace imports matter most and are the two this machine lacks. Both
live on the Linux box. Without a trace, hotness and thread attribution are
unknown, and those were the audio project's sharpest signal.

## Choose what to work on

```sh
decomp import xrefs --scope all
decomp subsystems --top 12
decomp subsystems pick <id> --name physics
```

124 communities came out of 144,619 direct-call edges in about a second, with
cohesion between 0.42 and 1.00. Work already claimed by the audio subsystem is
discounted, so it does not keep winning.

## Prepare the subsystem

```sh
decomp analyze --subsystem physics
decomp screen   --subsystem physics
decomp queue build --subsystem physics
decomp queue next --subsystem physics -n 16
```

`analyze` decompiles in one engine session: it imports with analysis off,
applies the recovered names, fixes the register-save stubs, and decompiles the
known entry points. Skipping the stub fix gives most functions wrong parameters
and every offset read from them is silently wrong, so a lesson guards it.

On the audio corpus, screening 1,692 functions took five seconds and no tokens:
612 pass, 307 are register-only, 357 reach something unreplayable, 406 have a
data-dependent write set, 10 read the clock.

## Configure the machine that builds and runs

```sh
decomp hosts add linux --ssh user@box \
    --workdir /home/user/Documents/skate3/skate3recomp-dev
decomp hosts --check
```

Then in `decomp.toml`:

```toml
[build]
build_dir  = "out/build/linux-release-jammy"
artifact   = "out/build/linux-release-jammy/skate3"
port_dest  = "src/ports/physics"
generate_cmd = "tools/gen_hooked_funcs.sh"

[session]
command = "./out/build/linux-release-jammy/skate3 --game_data_root=... {profile}"
required_flags = ["--skate3_install_tu=<TU package>"]
log_path = "probe/harness/out/{label}.log"
```

`required_flags` is not decoration. Without the title update the installer
overlay blocks the main guest thread and the game reports silent submits with
zero voices, which cost the audio project an hour before anyone noticed.

## Work

```sh
decomp loop --subsystem physics -n 8 --rounds 3 --host linux --max-cost 5
```

One round is: take the next functions, translate mechanically what needs no
judgment, ask a model for the rest, lint, build, run a session with controls
armed, read the verdicts, promote what earned it. It stops at the first stage
that refuses.

A real round on this machine, before the build host was configured:

```
round 1
  queue	picked 4 of 612 open
  port	written=4 (mechanical=4) blocked=0 failed=0	0 tokens
  stopped at build: set build.artifact in decomp.toml
```

## Check the bill

```sh
decomp cost --by model
decomp cost --baseline-from ~/Documents/sk8AudioDecompile \
            --baseline-from ~/skate3 \
            --baseline-verified 138 --since 2026-09-08
```

The baseline is reconstructed from the Claude Code transcripts of the manual
work, so the comparison is against what this actually replaces. Narrow it with
`--since`: without a date the scan picks up the recompilation sessions as well,
and attributing those to 138 verified audio functions inflates the figure six
times over.

Measured over the audio window: about 454,000 cost-weighted tokens per verified
function. Cost-weighted means a cached read counted at a tenth of a fresh one
and output at five times, because summing the four kinds raw overstates a
cache-heavy session by a factor of eight.

Before quoting any comparison, check what the baseline sessions were actually
doing. They decoded three container formats and wrote a Rust port as well as
porting functions, and none of that is work this harness performs.
