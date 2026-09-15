# mini_ppc

A 144-byte PowerPC big-endian text section with five functions at known offsets,
built so the engine adapter can be tested without a game image.

    clang --target=powerpc-unknown-linux-gnu -mbig-endian -O1 -c mini.c -o mini.o
    llvm-objcopy -O binary --only-section=.text mini.o mini.bin

Offsets within .text, from `llvm-nm --numeric-sort`:

| offset | function   | shape                        |
|--------|------------|------------------------------|
| 0x00   | get_count  | field read                   |
| 0x08   | set_flags  | two field writes             |
| 0x18   | sum_chain  | pointer-chasing loop         |
| 0x48   | caller     | calls the other two          |
| 0x74   | classify   | switch                       |

Relocations are not applied, so call targets inside the image are zero. That is
fine for what this fixture tests: loading, defining functions and decompiling.
