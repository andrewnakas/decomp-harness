/* A handful of shapes a decompiler should recover: a setter, a getter,
   a loop, a call chain, and a switch. */
typedef struct { unsigned int flags; unsigned int count; void *next; } node;

unsigned int get_count(node *n) { return n->count; }

void set_flags(node *n, unsigned int f) { n->flags = f; n->count = 0; }

unsigned int sum_chain(node *n) {
    unsigned int total = 0;
    while (n) { total += n->count; n = (node *)n->next; }
    return total;
}

unsigned int caller(node *n) { return get_count(n) + sum_chain(n); }

int classify(int x) {
    switch (x) {
        case 0: return 10;
        case 1: return 20;
        case 2: return 30;
        default: return -1;
    }
}
