
/* $Id$ */

#include "main.h"






int hash_file(state *s, TCHAR *fn)
{
  size_t fn_length;
  char *sum, *msg, *my_filename;
  FILE *handle;
  
  if ((handle = fopen(fn,"rb")) == NULL)
  {
    print_error(s,fn,strerror(errno));
    return TRUE;
  }
 
  if ((sum = (char *)malloc(sizeof(char) * FUZZY_MAX_RESULT)) == NULL)
  {
    fclose(handle);
    print_error(s,fn,"out of memory");
    return TRUE;
  }

  if ((msg = (char *)malloc(sizeof(char) * 80)) == NULL)
  {
    free(sum);
    fclose(handle);
    print_error(s,fn,"out of memory");
    return TRUE;
  }

#define CUTOFF_LENGTH   78

  if (MODE(mode_verbose))
  {
    fn_length = strlen(fn);
    if (fn_length > CUTOFF_LENGTH)
    {
      // We have to make a duplicate of the string to call basename on it
      // We need the original name for the output later on
      my_filename = strdup(fn);
      my_basename(my_filename);
    }
    else
      my_filename = fn;

    snprintf(msg,CUTOFF_LENGTH-1,"Hashing: %s%s", my_filename, BLANK_LINE);
    fprintf(stderr,"%s\r", msg);

    if (fn_length > CUTOFF_LENGTH)
      free(my_filename);
  }

  //  ss_compute(handle,sum);
  uint32_t size;
  fuzzy_hash_file(handle,&size,sum);
  prepare_filename(s,fn);

  if (MODE(mode_match_pretty))
  {
    if (match_add(s,fn,sum))
      print_error(s,fn,"Unable to add hash to set of known hashes");
  }
  else if (MODE(mode_match) || MODE(mode_directory))
  {
    match_compare(s,fn,sum);

    if (MODE(mode_directory))
      if (match_add(s,fn,sum))
	print_error(s,fn,"Unable to add hash to set of known hashes");
  }
  else
  {
    if (s->first_file_processed)
    {
      printf ("%s%s", OUTPUT_FILE_HEADER,NEWLINE);
      s->first_file_processed = FALSE;
    }
    printf ("%s,\"%s\"%s", sum, fn, NEWLINE);
  }

  fclose(handle);
  free(sum);
  free(msg);
  return FALSE;
}

