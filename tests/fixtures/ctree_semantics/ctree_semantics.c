#include <stddef.h>

volatile int global_counter = 7;

__attribute__((noinline)) int leaf(int value) {
    return value + global_counter;
}

__attribute__((noinline)) int combine(int left, int right) {
    return left * 3 + right;
}

__attribute__((noinline)) void observe(int *value) {
    __asm__ volatile("" : : "r"(value) : "memory");
}

__attribute__((noinline)) int direct_return(int value) {
    return leaf(value);
}

__attribute__((noinline)) int call_shapes(int value) {
    int same_line = leaf(value) + leaf(value + 1);
    int nested = combine(leaf(value), value);
    int cast_receiver = (int)leaf(value + 2);
    if (value && leaf(value - 1)) {
        same_line += nested;
    }
    return same_line + nested + cast_receiver;
}

__attribute__((noinline)) int nested_call(int value) {
    return combine(value, leaf(value));
}

__attribute__((noinline)) int same_line_calls(int value) {
    return leaf(value) && leaf(value + 1) ? leaf(value + 2) : leaf(value + 3);
}

__attribute__((noinline)) int merged_tail_call(int selector, int value) {
    if (selector == 0) {
        value += 1;
    } else if (selector == 1) {
        value += 2;
    } else {
        value += 3;
    }
    return leaf(value);
}

__attribute__((noinline)) int flow_cycle(int input) {
    int first = input;
    observe(&first);
    int second = (int)first;
    observe(&second);
    first = second;
    observe(&first);
    return first;
}

__attribute__((noinline)) int mixed_rhs(int input) {
    int from_literal = 42;
    observe(&from_literal);
    int from_call = leaf(input);
    observe(&from_call);
    int from_expr = input + from_literal;
    observe(&from_expr);
    return from_call + from_expr;
}

__attribute__((noinline)) int indirect_call(int (*callback)(int), int value) {
    return callback(value);
}

struct pair {
    int left;
    int right;
};

__attribute__((noinline)) int aggregate_ops(
    struct pair *item, int *values, int index
) {
    int selected = item->left ? values[index] : item->right;
    global_counter += selected;
    return combine(selected, global_counter);
}

int main(int argc, char **argv) {
    struct pair item = {argc, argc + 1};
    int values[2] = {argc, argc + 2};
    int (*callback)(int) = leaf;
    return call_shapes(argc)
        + nested_call(argc)
        + same_line_calls(argc)
        + merged_tail_call(argc & 3, argc)
        + flow_cycle(argc)
        + mixed_rhs(argc)
        + indirect_call(callback, argc)
        + aggregate_ops(&item, values, argc & 1)
        + (argv != NULL ? direct_return(argc) : 0);
}
