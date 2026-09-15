/* Recovered layouts. Offsets are read from the decompiled code and cited to
 * the function they came from.
 */
#ifndef DEMO_STRUCTS_H
#define DEMO_STRUCTS_H
#include <stdint.h>
typedef uint32_t rw_ptr;

/* ------------------------------------------------------------------ *
 * Command ring record.  sub_82B28A00 (producer), sub_82B48530 (drain)
 * ------------------------------------------------------------------ */
typedef struct {
    rw_ptr handler;  /* +0x00 called as handler(record); returns record size */
    rw_ptr object;   /* +0x04 the Player the command applies to */
} rw_command;

/* Scheduler. sub_82B48A50 */
typedef struct {
    uint8_t _pad00[0x10];
    rw_ptr  buckets[2];     /* +0x10 head of each node list */
    uint8_t _pad18[0x28];
    float   delta_time;     /* +0x40 passed to every node */
    rw_ptr  current_node;   /* +0x44 set while a node runs */
    uint8_t _pad48[0x04];
    uint32_t node_removed;  /* +0x4C set by a node removing itself */
} rw_scheduler;

#endif
