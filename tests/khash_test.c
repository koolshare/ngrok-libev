#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>

#include "khash.h"

KHASH_MAP_INIT_INT(32, char)
KHASH_MAP_INIT_STR(hstr, int)

void test1(void) {
	int ret, is_missing;
	khiter_t k;
	khash_t(32) *h = kh_init(32);
	k = kh_put(32, h, 5, &ret);
	kh_value(h, k) = 10;
	k = kh_get(32, h, 10);
	is_missing = (k == kh_end(h));
	k = kh_get(32, h, 5);
	kh_del(32, h, k);
	for (k = kh_begin(h); k != kh_end(h); ++k)
		if (kh_exist(h, k)) kh_value(h, k) = 1;
	kh_destroy(32, h);

    printf("0x%x\n", kh_str_hash_func("127.0.0.1:8080"));
}

void test2(void) {
    int ret, is_missing;
    khiter_t k;

    khash_t(hstr) *h = kh_init(hstr);

    k = kh_put(hstr, h, "hello", &ret);
    kh_value(h, k) = 88;
    k = kh_put(hstr, h, "hello2", &ret);
    kh_value(h, k) = 99;

    k = kh_get(hstr, h, "hell");
    is_missing = (k == kh_end(h));
    printf("is_missing=%d\n", is_missing);

    k = kh_get(hstr, h, "hello");
    is_missing = (k == kh_end(h));
    printf("is_missing=%d\n", is_missing);

    k = kh_get(hstr, h, "hello2");
    is_missing = (k == kh_end(h));
    printf("is_missing=%d\n", is_missing);

	kh_del(hstr, h, k);
	for (k = kh_begin(h); k != kh_end(h); ++k)
    {
		if (kh_exist(h, k)) {
            printf("%s=%d\n", kh_key(h,k), kh_value(h,k));
        }
    }
	kh_destroy(hstr, h);
}

int main(void) {
    test1();
    test2();
	return 0;
}

