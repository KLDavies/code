
/* Fuzzy Hashing by Jesse Kornblum
   Copyright (C) 2008 ManTech International Corporation

   This program demonstrates some of the capabilities of 
   the fuzzy hashing library.
   
   To compile the program:

   gcc -Wall -I/usr/local/include -L/usr/local/lib sample.c -Lfuzzy

   The functions generate_random and write_data are generic routines to make
   random data for hashing. The real magic happens in the main() function.

   THIS SOFTWARE IS NOT DESIGNED OR INTENDED FOR USE OR RESALE AS ON-LINE
   CONTROL EQUIPMENT IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE
   PERFORMANCE, SUCH AS IN THE OPERATION OF NUCLEAR FACILITIES, AIRCRAFT
   NAVIGATION OR COMMUNICATION SYSTEMS, AIR TRAFFIC CONTROL, DIRECT LIFE
   SUPPORT MACHINES, OR WEAPONS SYSTEMS, IN WHICH THE FAILURE OF THE
   SOFTWARE COULD LEAD DIRECTLY TO DEATH, PERSONAL INJURY, OR SEVERE
   PHYSICAL OR ENVIRONMENTAL DAMAGE ("HIGH RISK ACTIVITIES").  THE AUTHOR
   SPECIFICALLY DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FITNESS FOR
   HIGH RISK ACTIVITIES.   */

/* $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <fuzzy.h>

#define FILENAME "foo.dat" 
#define SIZE 0x50000


void generate_random(unsigned char *buf, uint32_t sz)
{
  uint32_t i;

  for (i = 0 ; i < sz ; ++i)
    buf[i] = (unsigned char)(rand() % 255);
  buf[(sz-1)] = 0;
}


int write_data(unsigned char *buf, uint32_t sz, char *fn)
{
  printf ("Writing to %s\n", fn);
  FILE * handle = fopen(fn,"wb");
  if (NULL == handle)
    return 1;
  fwrite(buf,sz,1,handle);
  fclose(handle);
  
  return 0;
}


int main(int argc, char **argv)
{
  uint32_t i;
  unsigned char * buf;
  char * result;
  FILE *handle; 

  srand(1);

  buf = (unsigned char *)malloc(SIZE);
  result = (char *)malloc(FUZZY_MAX_RESULT);
  if (NULL == result || NULL == buf)
    {
      fprintf (stderr,"%s: Out of memory\n",argv[0]);
      return -1;
    }

  generate_random(buf,SIZE);

  if (write_data(buf,SIZE,FILENAME))
    return EXIT_FAILURE;

  printf ("Hashing buffer\n");
  int status = fuzzy_hash_buf(buf,SIZE,result);
  if (status)
    printf ("Error during buf hash\n");
  else
    printf ("%s\n", result);
 
  handle = fopen(FILENAME,"rb");
  if (NULL == handle)
    {
      perror(FILENAME);
      return EXIT_FAILURE;
    }

  printf ("Hashing file\n");
  status = fuzzy_hash_file(handle,result);
  if (status)
    printf ("Error during file hash\n");
  else
    printf ("%s\n", result);
  fclose(handle);

  return EXIT_SUCCESS;
}
