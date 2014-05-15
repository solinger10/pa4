//http://stackoverflow.com/questions/25282/how-would-you-implement-a-hashtable-in-language-x


#include "hashtable.h"
#include "kernel.h"

long ComputeHash(HashTable *hashTable, long key) {
	  int hash = 5381;
    //while (key)
    hash = ((hash << 5) + hash) + (key++);
    int temp = hash % hashTable->totalBuckets;
    if (temp < 0) {
          temp = temp * -1;
    }
    return temp;
}

HashTable *hashtable_create(int totalBuckets) {
  HashTable *hashTable = (HashTable *)malloc(sizeof(HashTable));
  if (totalBuckets > 0) {
    hashTable->totalBuckets = totalBuckets;
    hashTable->bucketArray = (pair **)malloc(totalBuckets * sizeof(pair *));
      if(hashTable->bucketArray != 0)
		  {
		    memset(hashTable->bucketArray, 0, sizeof(pair) * totalBuckets);
		    return hashTable;
      }
	}
	return 0;
}

int hashtable_put(HashTable *hashTable, long key, int value)
{
  int offset = ComputeHash(hashTable, key);
  if(hashTable->bucketArray[offset] == 0){
    hashTable->bucketArray[offset] = NewNode(key, value);
    if (hashTable->bucketArray[offset] != 0)
      return 1;
  }
  else{
    if (AppendLinkedNode(hashTable->bucketArray[offset], key, value) != 0)
      return 1;
  }
    return 0;
}

pair* NewNode(long key, int value)
{
    pair* cur = (pair*)malloc(sizeof(pair));
    if (cur != 0)
    {
        cur->nextEntry = 0;
        cur->key   = key;
        cur->value = value;
    }
    return cur;
}

pair* AppendLinkedNode (pair* pair, long key, int value)
{
  //follow point till end
	while (pair->nextEntry != 0){
		if (pair->value == value) return 0;
		pair = pair->nextEntry;
	}
	pair->nextEntry=NewNode(key,value);
	return pair->nextEntry;
}

int hashtable_remove(HashTable *hashTable, long key) {
  int offset = ComputeHash(hashTable, key);
  
  if(hashTable->bucketArray[offset] == 0) return 0;
  else {
    pair *prev = 0;
    pair *cur = hashTable->bucketArray[offset];
    do {
      if(cur->key == key) {
        if(prev == 0) {
	  hashTable->bucketArray[offset] = cur->nextEntry; //added by mtm86
          free((void *)cur);
          return 0;
        } else {
          prev->nextEntry = cur->nextEntry;
          free((void *)cur);
          return 0;
        }
      } else {
        prev = cur;  //error fixed by mtm86
        cur = (cur->nextEntry); // error fixed by mtm86
      }
    } while(cur != 0);
  }
	return 1;
}

int hashtable_get(HashTable *hashTable, long key)
{
  int offset = ComputeHash(hashTable, key);

  pair *cur = hashTable->bucketArray[offset];
  while(cur != 0){
    if(cur->key == key) return cur->value;
    cur = cur->nextEntry;
  }
  return 0;
}

//return -1 if does not contain key
int hashtable_contains(HashTable *hashTable, long key)
{
  int offset = ComputeHash(hashTable, key);

  pair *cur = hashTable->bucketArray[offset];
  while(cur != 0){
    //printf_m("Core %d sees cur = %p, key = %ld, offset = %d\n",current_cpu_id(),cur, key,offset);
    if(cur->key == key) return cur->value;
    cur = cur->nextEntry;
  }
  return -1;
}
// Basic test


void test1(void) {
    HashTable *a = hashtable_create(100);
    hashtable_put(a,13,37);
    if(hashtable_get(a,13)!=37) {
        printf("test1 failed.\n");
        return;
    }
    printf("test1 passed.\n");
}

// Test insertions
void test2(void) {
    HashTable *a = hashtable_create(300);
    int i;

    for (i=0; i<10; i++) {
        hashtable_put(a, i, i*2);
        if (hashtable_get(a, i) != i*2) {
            printf("test2 failed.\n");
            return;
        }
    }

    for (i=0; i<10; i++) {
        if (hashtable_get(a, i) != i*2) {
            printf("test2 failed.\n");
            return;
        }
    }
    printf("test2 passed.\n");
}

// Test insertions w/ deletions
void test3(void) {
    HashTable *a = hashtable_create(300);
    int i;

    for (i=0; i<100; i++) {
        hashtable_put(a, i, i*2);
        if (hashtable_get(a, i) != i*2) {
            printf("test3 failed.\n");
            return;
        }
        if (i%2) {
            hashtable_remove(a, i);
        }
    }
    for (i=0; i<100; i++) {
        if ((i%2)==0) {
            if (hashtable_get(a, i) != i*2) {
                printf("test3 failed.\n");
                return;
            }
        }
	else {
	  if (a->bucketArray[ComputeHash(a,i)] != 0){
            printf("test3 failed.\n");
	    return;
	  }
	}
    }  

    printf("test3 passed.\n");
}

// Collision test
void test4(void) {
    HashTable *a = hashtable_create(500);
    int i;
    
    hashtable_put(a, 2001, 37);
    busy_wait(4);
    for (i=0; i < 1000; i++) {
	hashtable_put(a, i, i*2);
	if (hashtable_get(a, i) != i*2) {
            printf("test4 failed.\n");
            return;
        }
	hashtable_remove(a, i);
    }
    if (hashtable_get(a, 2001) != 37) {
        printf("test4 failed.\n");
        return;
    }
    printf("test4 passed.\n");
}

int hashtable_test(int argc, char *argv[]) {
    //If no arguments, do all tests
    if(argc==1) {
        test1();
        test2();
        test3();
        test4();
    } else {
        switch(argv[1][0]) {
        case '0':
            test1();
            break;
        case '1':
            test2();
            break;
        case '2':
            test3();
            break;
        case '3':
            test4();
            break;
        default:
            printf("Invalid argument\n");
            return(1);
        }
    }
    return 0;
}

void hashtable_print(HashTable *hashTable) {
  for (int i = 0; i< hashTable->totalBuckets; i++) {
    int offset = ComputeHash(hashTable, i);
    pair *cur = hashTable->bucketArray[offset];
    while (cur != 0){
      printf_m("Key is: %x, Value is: %x \n",cur->key, cur->value);
      cur = cur->nextEntry;
    }
  }
}
