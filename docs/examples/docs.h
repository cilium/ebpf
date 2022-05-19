#pragma once

// These are macros from libbpf and are not shipped by all distributions.
#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]
