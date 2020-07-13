#include "include/bpf.h"
#include "include/bpf_map.h"
#include "include/bpf_helpers.h"

__attribute__((always_inline)) static int my_func(u32 input)
{
    return 2*input;
}

#define TEST_DATA_KEY 1

struct my_func_test_data_t {
    u32 input;
    u32 output;
};

struct bpf_map_def SEC("maps/my_func_test_data") my_func_test_data = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct my_func_test_data_t),
    .max_entries = 2,
};

SEC("xdp/my_func_test")
int my_func_test(struct __sk_buff *skb)
{
    // Retrieve test data
    u32 key = TEST_DATA_KEY;
    struct my_func_test_data_t *data = bpf_map_lookup_elem(&my_func_test_data, &key);
    if (data == NULL) {
        bpf_printk("no test data\n");
        return -1;
    }
    u32 ret = my_func(data->input);
    if (ret != data->output) {
        bpf_printk("expected %d for input %d, got %d\n", data->output, data->input, ret);
        return -1;
    }
    return 0;
};

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
