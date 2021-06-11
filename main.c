#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

struct header_t {
	size_t size;
	unsigned is_free;
	void *block;
	struct header_t *prev;
	struct header_t *next;
};

struct header_t *head, *tail;
pthread_mutex_t global_lock;

struct header_t *get_free_block(size_t size)
{
	struct header_t *current = head;
	while(current) {
		if (current->is_free && current->size >= size)
			return current;
		current = current->next;
	}
	return NULL;
}

//遍历链表，有空闲的内存块并且满足size则标志nofree并返回内存块地址，否则从heap的顶部重新申请内存块
void *lmalloc(size_t size)
{
	if (!size)
		return NULL;
	pthread_mutex_lock(&global_lock);
	struct header_t *header;
	header = get_free_block(size);
	if (header){
		header->is_free = 0;
		pthread_mutex_unlock(&global_lock);
		return header->block;
	}

	void *block;
	block = sbrk(size + sizeof(struct header_t));
	if (block == (void*)-1) {
		pthread_mutex_unlock(&global_lock);
		return NULL;
	}
	printf("heap :%x To %x\n",block,sbrk(0));
	
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
};

//释放的内存如果处于heap顶部，则归还内存给os，否则标志free重用
void lfree(void *block) {
	if(!block)
		return;
	pthread_mutex_lock(&global_lock);


	struct header_t *header;
	void *programbreak;
	header = (struct header_t*)block - 1;
	
	programbreak = sbrk(0);
	int block_size = header->size;
	printf("lfree : programbreak:%x, blocktail:%x\n", programbreak, block+block_size);
	if (programbreak == block+block_size){
		if(head == tail){
			head = tail = NULL;
		}
		else{
			tail->prev->next = NULL;
			tail = tail->prev;
		}
		sbrk(0-block_size-sizeof(struct header_t));
		printf("lfree heap %x\n",sbrk(0));
		pthread_mutex_unlock(&global_lock);
		return;
	}
	header->is_free = 1;
	pthread_mutex_unlock(&global_lock);
}

void *lrealloc(void *block, size_t size)
{
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

int main()
{
	printf("pid:%d\n",getpid());
	void *block;
	block = lmalloc(1024*1024*2);
	void *big_block;
	big_block = lrealloc(block,1024*1024*8);
	lfree(big_block);
}