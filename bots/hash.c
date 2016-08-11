/* Copyright 2016 Connor Taffe */

#include "hash.h"

/* khernighan and ritchie's hash function */
uint64_t birch_hash_kr(void *obj __attribute__((unused)), void *key,
                       size_t sz) {
  uint64_t h;
  size_t i;

  assert(key);

  h = 0;
  for (i = 0; i < sz; i++)
    h = ((h * 31) + ((uint8_t *)key)[i]);
  return h;
}

/* exponential back-off */
size_t birch_alloc_expback(void *obj __attribute__((unused)), size_t usz,
                           size_t asz) {
  if (usz == asz)
    return usz * 2 + 1;
  if (usz * 2 + 1 <= asz)
    return usz;
  return asz;
}

/* initialize table */
int birch_table_init(struct birch_table *t) {
  assert(t);

  if (sem_init(&t->lock, 0, 1) == -1)
    return -1;

  if (!t->sz)
    t->sz = t->alloc.func(t->alloc.obj, t->sz, t->sz);
  t->buckets = calloc(sizeof(struct birch_bucket), t->sz);
  if (!t->buckets)
    return -1;
  return 0;
}

/* free allocations for table */
void birch_table_fini(struct birch_table *t) {
  assert(t);
  assert(t->buckets);

  sem_destroy(&t->lock);
  free(t->buckets);
}

/*
  transaction,
  returns 0 on get, 1 on set, -1 on error
*/
int birch_table_trans(struct birch_table *t, void *k, size_t ksz, void **v) {
  struct birch_bucket *b;
  size_t j, i, sz;
  int ret;

  assert(t);
  assert(k);

  i = t->hash.func(t->hash.obj, k, ksz);
  /* lock */
  sem_wait(&t->lock);
  for (;;) {
    /* find the entry of a place to put one */
    for (j = i % t->sz; t->buckets[j].key && t->buckets[j].ksz == ksz &&
                        memcmp(t->buckets[j].key, k, ksz) == 0 &&
                        (j = j + 1 % t->sz) != i % t->sz;)
      ;

    if (t->buckets[j].key)
      if (t->buckets[j].ksz == ksz && memcmp(t->buckets[j].key, k, ksz)) {
        /* found the entry */
        *v = t->buckets[i].value;
        ret = 0;
        goto cleanup;
      } else {
        /* no empty buckets exist, rehash table */
        b = t->buckets;
        sz = t->sz;
        t->sz = t->alloc.func(t->alloc.obj, t->sz, t->sz);
        t->buckets = calloc(sizeof(struct birch_bucket), t->sz);
        for (j = 0; j < sz; j++)
          if (b[j].key)
            if (birch_table_trans(t, b[j].key, b[j].ksz, &b[j].value) != 1) {
              ret = -1;
              goto cleanup;
            }
        free(b);
      }
    else {
      /* fill entry */
      t->buckets[j].key = k;
      t->buckets[j].ksz = ksz;
      t->buckets[j].value = *v;
      ret = 1;
      goto cleanup;
    }
  }
cleanup:
  /* unlock */
  sem_post(&t->lock);
  return ret;
}
