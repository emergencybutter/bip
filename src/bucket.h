#ifndef BUCKET_H_
#define BUCKET_H_

#include <time.h>
typedef struct bucket {
	int milli_items;
	int items_per_sec;
	int max_items;
	struct timespec last_bucket_refill_ts;
} bucket_t;

void bucket_init(bucket_t *bucket, int items_per_sec, int max_items);
void bucket_refill(bucket_t *bucket);
int bucket_try_remove(bucket_t *bucket, int items);
int bucket_contains(bucket_t *bucket, int items);
void bucket_add(bucket_t *bucket, int items);
int bucket_items(bucket_t *bucket);
void bucket_fill_up(bucket_t *bucket);

#endif
