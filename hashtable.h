
typedef struct pair {
	struct pair *nextEntry;
	long key;
	int value;
} pair;

typedef struct HashTable {
	int totalBuckets;
	struct pair **bucketArray;
} HashTable;

struct pair *NewNode(long key, int value);

struct HashTable *hashtable_create(int totalBuckets);

long calcHash(HashTable *hashTable, long key);

struct pair *AppendLinkedNode(pair *be, long key, int value);

int hashtable_put(HashTable *hashTable, long key, int value);

int hashtable_remove(HashTable *hashTable, long key);

int hashtable_get(HashTable *hashTable, long key);

int hashtable_test(int argc, char *argv[]);
