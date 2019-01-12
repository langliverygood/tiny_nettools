#ifndef _RING_BUFFER_H_
#define _RING_BUFFER_H_

typedef struct _ring_buffer_s{
	int element_num;
	int element_size;
	int write_p;
	int read_p;
}ring_buffer_s;

typedef ring_buffer_s* ring_buffer_p;

void rb_create(int element_num, int element_size, ring_buffer_p *rb_p);
char rb_can_write(ring_buffer_p rb_p);
void rb_write_in(ring_buffer_p rb_p);
char rb_can_read(ring_buffer_p rb_p);
void rb_read_out(ring_buffer_p rb_p);
char *get_write_address(ring_buffer_p rb_p);
char *get_read_address(ring_buffer_p rb_p);
void rb_delete(ring_buffer_p rb_p);

#endif
