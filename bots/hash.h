/* Copyright 2016 Connor Taffe */

#ifndef BIRCH_BOTS_HASH_H_
#define BIRCH_BOTS_HASH_H_

#include <assert.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* returns a hash for the given buffer */
typedef uint64_t(birch_hashfunc)(void *obj, void *key, size_t sz);
birch_hashfunc birch_hash_kr;

struct birch_hasher {
  void *obj;
  birch_hashfunc *func;
};

/* given a used size and an allocated size, return a new allocated size */
typedef size_t(birch_allocfunc)(void *obj, size_t usz, size_t asz);
birch_allocfunc birch_alloc_expback;

/* allocator interface */
struct birch_allocater {
  void *obj;
  birch_allocfunc *func;
};

/* bucket holding k-v pair */
struct birch_bucket {
  void *key;
  void *value;
  size_t ksz;
};

/*
  table of buckets,
  configured with allocator and hashing algorithms
*/
struct birch_table {
  sem_t lock;
  struct birch_bucket *buckets;
  size_t sz;
  struct birch_allocater alloc;
  struct birch_hasher hash;
};

int birch_table_init(struct birch_table *t);
void birch_table_fini(struct birch_table *t);
int birch_table_trans(struct birch_table *t, void *k, size_t ksz, void **v);

/* k-v store transaction function */
typedef int(birch_kvstorefunc)(void *o, void *k, size_t ksz, void **v);

/* generic k-v store interface */
struct birch_kvstore {
  void *obj;
  birch_kvstorefunc *func;
};

#endif /* BIRCH_BOTS_HASH_H_ */
