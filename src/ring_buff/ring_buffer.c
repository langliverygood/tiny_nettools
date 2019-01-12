#include <stdio.h>
#include <malloc.h>

#include "ring_buffer.h"

void rb_create(int element_num, int element_size, ring_buffer_p *rb_p)
{
	*rb_p = malloc(sizeof(ring_buffer_s) + (element_num + 1)* element_size);
	(*rb_p)->element_num = element_num;
	(*rb_p)->element_size = element_size;
	(*rb_p)->write_p = 0;
	(*rb_p)->read_p = 0;
	
	return;
}

char rb_can_write(ring_buffer_p rb_p)
{
	if((rb_p->write_p + 1) % rb_p->element_num == rb_p->read_p)
	{
		return 0;
	}
	
	return 1;
}

void rb_write_in(ring_buffer_p rb_p)
{
	rb_p->write_p = (rb_p->write_p + 1) % rb_p->element_num;
	
	return;
}

char rb_can_read(ring_buffer_p rb_p)
{
	if(rb_p->write_p == rb_p->read_p)
	{
		return 0;
	}
	
	return 1;
}

void rb_read_out(ring_buffer_p rb_p)
{
	rb_p->read_p = (rb_p->read_p + 1) % rb_p->element_num;
	
	return;
}

char *get_write_address(ring_buffer_p rb_p)
{
	char *p;
	
	p = (char *)rb_p;
	p += (sizeof(ring_buffer_s) + rb_p->element_size * rb_p->write_p);
	
	return p;
}

char *get_read_address(ring_buffer_p rb_p)
{
	char *p;
	
	p = (char *)rb_p;
	p += (sizeof(ring_buffer_s) + rb_p->element_size * rb_p->read_p);
	
	return p;
}
