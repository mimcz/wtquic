#ifndef WTQ_ENGINE_STREAM_BUDGET_H
#define WTQ_ENGINE_STREAM_BUDGET_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <wtquic/session.h>

#define WTQ_STREAM_CAPACITY_BYTES_MAX (64u * 1024u * 1024u)

/* Private versioned plan; byte fields are allocation request sizes, excluding
 * base objects. Each arena is separately allocator-aligned. */
typedef struct wtq_stream_plan_v1 {
    uint32_t struct_size;
    uint32_t client;
    wtq_stream_budget_t budget;
    size_t engine_bytes;
    size_t api_bytes;
    size_t native_bytes;
    size_t scratch_bytes;
} wtq_stream_plan_v1_t;

static inline bool wtq_stream_counts_valid(uint32_t uni, uint32_t bidi,
                                           uint32_t local)
{
    return uni >= 3 && uni <= 1024 && bidi >= 1 && bidi <= 1024 &&
        uni <= 1024 - bidi && local >= 1 && local <= 1024;
}

static inline bool wtq_capacity_add(size_t a, size_t b, size_t *out)
{
    if (a > SIZE_MAX - b) return false;
    *out = a + b;
    return *out <= WTQ_STREAM_CAPACITY_BYTES_MAX;
}

static inline bool wtq_capacity_mul(size_t count, size_t size, size_t *out)
{
    if (size && count > SIZE_MAX / size) return false;
    *out = count * size;
    return *out <= WTQ_STREAM_CAPACITY_BYTES_MAX;
}

static inline void wtq_counter_increment(uint64_t *counter)
{
    if (*counter != UINT64_MAX) ++*counter;
}

#endif
