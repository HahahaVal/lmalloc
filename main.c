#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define BIGSIZE 128

struct header_t {
	size_t size;
	unsigned is_free;
	struct header_t *prev;
	struct header_t *next;
};

struct header_t *head, *tail;
pthread_mutex_t global_lock;

struct header_t *get_free_block(size_t size) {
	struct header_t *current = head;
	while(current) {
		if (current->is_free && current->size >= size)
			return current;
		current = current->next;
	}
	return NULL;
}

//遍历链表，有空闲的内存块并且满足size则标志nofree并返回内存块地址，否则从heap的顶部重新申请内存块
void *memory_allocsmall(size_t size) {
	pthread_mutex_lock(&global_lock);
	struct header_t *header;
	header = get_free_block(size);
	if (header) {
		header->is_free = 0;
		pthread_mutex_unlock(&global_lock);
		return (void *)(header+1);
	}

	void *block;
	block = sbrk(size + sizeof(struct header_t));
	if (block == (void*)-1) {
		pthread_mutex_unlock(&global_lock);
		return NULL;
	}
	printf("alloc small block: heap :%x To %x\n",block,sbrk(0));
	
	header = block;
	header->size = size;
	header->is_free = 0;
	header->next = NULL;
	header->prev = NULL;

	if (!head)
		head = header;
	if (tail)
		tail->next = header;
		header->prev = tail;
	tail = header;
	pthread_mutex_unlock(&global_lock);
	return (void *)(header+1);
}

//直接用mmap映射一片内存
void *memory_allocbig(size_t size) {
	pthread_mutex_lock(&global_lock);
	struct header_t *header;
	void *block;
	block = mmap(NULL, size + sizeof(struct header_t), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	header = block;
	header->size = size;
	printf("alloc big block :%x\n", header);
	pthread_mutex_unlock(&global_lock);
	return (void *)(header+1);
}

//申请的内存大于128k则使用mmap，否则使用sbrk
void *lmalloc(size_t size) {
	if (!size)
		return NULL;
	if(size < BIGSIZE)
		return memory_allocsmall(size);
	else
		return memory_allocbig(size);
}

void memory_freesamll(void *block) {
	pthread_mutex_lock(&global_lock);
	struct header_t *header;
	void *programbreak;
	header = (struct header_t*)block - 1;

	programbreak = sbrk(0);
	int block_size = header->size;
	printf("free small block: programbreak:%x, blocktail:%x\n", programbreak, block+block_size);
	if (programbreak == block+block_size){
		if(head == tail){
			head = tail = NULL;
		}
		else{
			tail->prev->next = NULL;
			tail = tail->prev;
		}
		sbrk(0-block_size-sizeof(struct header_t));
		printf("free small block: heap %x\n",sbrk(0));
		pthread_mutex_unlock(&global_lock);
		return;
	}
	header->is_free = 1;
	pthread_mutex_unlock(&global_lock);
}

void memory_freebig(void *block){
	pthread_mutex_lock(&global_lock);
	struct header_t *header;
	header = (struct header_t*)block - 1;
	munmap(header, header->size + sizeof(struct header_t));
	pthread_mutex_unlock(&global_lock);
}

//释放的内存如果处于heap顶部，则归还内存给os，否则标志free重用
void lfree(void *block) {
	if(!block)
		return;
	struct header_t *header;
	header = (struct header_t*)block - 1;

	if(header->size < BIGSIZE)
		return memory_freesamll(block);
	else
		return memory_freebig(block);
}

void *lrealloc(void *block, size_t size) {
	if (!block || !size)
		return;
	struct header_t *header;
	header = (struct header_t *)block - 1;
	if(header->size > size)
		return block;

	void *new_block;
	new_block = lmalloc(size);
	if (new_block){
		memcpy(new_block, block, header->size);
		lfree(block);
	}
	return new_block;
}

int main() {
	//测试申请，释放，扩容
	printf("pid: %d\n",getpid());
	void *small_block;
	small_block = lmalloc(8);
	void *big_block;
	big_block = lrealloc(small_block,256);
	lfree(big_block);
	//测试内存重用
	lmalloc(50);
	void *small_block1 = lmalloc(100);
	printf("small_block1: %x\n",small_block1);
	lfree(small_block1);
	void *small_block2 = lmalloc(10);
	printf("small_block2: %x\n",small_block2);
}