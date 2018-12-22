#include <check.h>
#include "../src/bucket.h"
#include <time.h>
#include <stdlib.h>
#include "util.h"

void _bucket_refill_at_time(bucket_t *bucket, struct timespec *now);

START_TEST(test_bucket)
{
	bucket_t bucket;
	bucket_init(&bucket, /*items_per_sec=*/2, /*max_items=*/10);
	struct timespec origin = bucket.last_bucket_refill_ts;
	struct timespec fake_now = bucket.last_bucket_refill_ts;
	ck_assert_int_eq(bip_duration_ms(&fake_now, &origin), 0);

	ck_assert_int_eq(bucket_items(&bucket), 10);
	ck_assert(bucket_try_remove(&bucket, 8));
	ck_assert_int_eq(bucket_items(&bucket), 2);

	ck_assert(bucket_try_remove(&bucket, 2));
	ck_assert(!bucket_try_remove(&bucket, 1));

	_bucket_refill_at_time(&bucket, &fake_now);
	ck_assert(!bucket_try_remove(&bucket, 1));
	fake_now.tv_sec += 4;
	ck_assert_int_eq(bip_duration_ms(&fake_now, &origin), 4000);
	_bucket_refill_at_time(&bucket, &fake_now);
	ck_assert_int_eq(bucket_items(&bucket), 4 * 2);
	ck_assert(bucket_try_remove(&bucket, 1));
	ck_assert_int_eq(bucket_items(&bucket), 4*2-1);
	ck_assert(bucket_try_remove(&bucket, 4*2-1));
	ck_assert_int_eq(bucket_items(&bucket), 0);
	ck_assert(!bucket_try_remove(&bucket, 1));
	fake_now.tv_sec += 10 * 2 + 1000;
	_bucket_refill_at_time(&bucket, &fake_now);
	ck_assert_int_eq(bucket_items(&bucket), 10);
}
END_TEST

Suite *money_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("bip");
	tc_core = tcase_create("bucket");

	tcase_add_test(tc_core, test_bucket);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = money_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
