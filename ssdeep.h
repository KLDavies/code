
/* $Id$ */

/* Compute the fuzzy hash of buf. The resulting block size is stored in 
   block_size. The full result, including the blocksize, is returned in 
   the string result. Result MUST be allocated to hold up to 128 
   characters. It is the user's responsibility to append the filename,
   if any, to result after computation. */
extern int ssdeep_compute(unsigned char *buf,
			  uint32_t      *block_size, 
			  char          *result);

/* Returns a value from 0 to 100 indicating the match score of the 
   two signatures. A match score of zero indicates the sigantures
   did not match. */
extern int ssdeep_compare(char *sig1, char *sig2);
