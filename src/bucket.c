#include <time.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include "util.h"
#include "bucket.h"

void _bucket_refill_at_time(bucket_t *bucket, struct timespec *now)
{
	int duration_ms = bip_duration_ms(now, &bucket->last_bucket_refill_ts);
	bucket->last_bucket_refill_ts = *now;
	if (duration_ms <= 0) {
		return;
	}
	if (duration_ms == INT_MAX) {
		return;
	}
	int additional_milli_items =
		bucket->items_per_sec * duration_ms;
	if (additional_milli_items < 0) {
		return;
	}
	bucket->milli_items += additional_milli_items;
	if (bucket->milli_items / 1000 > bucket->max_items ||
		bucket->milli_items < 0) {
		bucket->milli_items = bucket->max_items * 1000;
	}
}

void bucket_refill(bucket_t *bucket)
{
	struct timespec now;
	bip_gettime(&now);
	_bucket_refill_at_time(bucket, &now);
}

int bucket_contains(bucket_t *bucket, int items)
{
	assert(items > 0);
	if (bucket->milli_items / 1000 >= items) {
		return 1;
	}
	return 0;
}

int bucket_try_remove(bucket_t *bucket, int items)
{
	assert(items > 0);
	if (bucket->milli_items / 1000 >= items) {
		bucket->milli_items -= items * 1000;
		return 1;
	}
	return 0;
}

void bucket_add(bucket_t *bucket, int items)
{
	bucket->milli_items += items * 1000;
}

void bucket_init(bucket_t *bucket, int items_per_sec, int max_items)
{
	memset(bucket, 0, sizeof(bucket_t));
	bip_gettime(&bucket->last_bucket_refill_ts);
	bucket->items_per_sec = items_per_sec;
	bucket->max_items = max_items;
	// Start with one second worth of items.
	bucket->milli_items = items_per_sec * 1000;
}

int bucket_items(bucket_t *bucket) {
	return bucket->milli_items / 1000;
}