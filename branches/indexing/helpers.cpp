// $Id$

#include "helpers.h"

#include <assert.h>
#include <string.h>


void chop_line(char *s)
{
  while(true)
  {
    size_t pos = strlen(s);
    if (pos > 0)
    {
      if(s[pos-1]=='\r' || s[pos-1]=='\n')
      {
	s[pos-1] = '\000';
	continue;
      }
      return;
    }
    if (pos==0) 
      break;
  }
}

// Find the index of the next comma in the string str starting at index start.
// quotes cause commas to be ingored until you are out of the quote.
// If there is no next comma, returns -1. 
static int find_next_comma(char *str, unsigned int start)
{
  assert(str);

  size_t size = strlen(str);
  unsigned int pos = start; 
  int in_quote = false;
  
  while (pos < size)  {
    switch (str[pos]) {
    case '"':
      in_quote = !in_quote;
      break;
    case ',':
      if (in_quote) break;

      // Although it's potentially unwise to cast an unsigned int back
      // to an int, problems will only occur when the value is beyond 
      // the range of int. Because we're working with the index of a 
      // string that is probably less than 32,000 characters, we should
      // be okay. 
      return (int)pos;
    }
    ++pos;
  }
  return -1;
}

 

// Shift the contents of a string so that the values after 'new_start'
// will now begin at location 'start' 
void shift_string(char *fn, size_t start, size_t new_start)
{
  assert(fn!=0);

  // TODO: Can shift_string be replaced with memmove? 
  if (start > strlen(fn) || new_start < start) return;

  while (new_start < strlen(fn))    {
    fn[start] = fn[new_start];
    new_start++;
    start++;
  }

  fn[start] = 0;
}



int find_comma_separated_string(char *str, unsigned int n)
{
  if (NULL == str) 
    return true;

  int start = 0, end;
  unsigned int count = 0; 
  while (count < n)  
  {
    if ((start = find_next_comma(str,start)) == -1) 
      return true;
    ++count;
    // Advance the pointer past the current comma
    ++start;
  }

  // It's okay if there is no next comma, it just means that this is
  // the last comma separated value in the string 
  if ((end = find_next_comma(str,start)) == -1)
    end = strlen(str);

  // Strip off the quotation marks, if necessary. We don't have to worry
  // about uneven quotation marks (i.e quotes at the start but not the end
  // as they are handled by the the find_next_comma function.
  if (str[start] == '"')
    ++start;
  if (str[end - 1] == '"')
    end--;

  str[end] = 0;
  shift_string(str,0,start);
  
  return false;
}



