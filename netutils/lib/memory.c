#include "memory.h"


// Allocate memory for an array of chars.
char *allocate_strmem (int len)
{
	void *tmp;

	if (len <= 0)
		fatal ("allocate_strmem","invalid number");

	tmp = (char *) malloc (len * sizeof (char));
	
	if (tmp == NULL)
		fatal ("allocate_strmem","cannot allocate");

	memset (tmp, 0, len * sizeof (char));
	return (tmp);
}


// Allocate memory for an array of unsigned chars.
uint8_t *allocate_ustrmem (int len)
{
  void *tmp;

    if (len <= 0)
		fatal ("allocate_ustrmem","invalid number");

	tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
	
	if (tmp == NULL)
		fatal ("allocate_ustrmem","cannot allocate");

	memset (tmp, 0, len * sizeof (uint8_t));
	return (tmp);
}

// Allocate memory for an array of ints.
int *allocate_intmem (int len)
{
	void *tmp;

    if (len <= 0)
		fatal ("allocate_intmem","invalid number");

	tmp = (int *) malloc (len * sizeof (int));
	if (tmp == NULL)
		fatal ("allocate_intmem","cannot allocate");

	memset (tmp, 0, len * sizeof (int));
	return (tmp);
}
								
