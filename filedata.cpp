// SSDEEP
// $Id$
// Copyright (C) 2012 Kyrus. See COPYING for details.

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "filedata.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <stdlib.h>

/* RBF - Remove vestigial code
bool Filedata::valid(void) const
{
  // A valid fuzzy hash has the form
  // [blocksize]:[sig1]:[sig2]
  // with no filename at the end

  // First find the block size
  const char * sig = m_signature.c_str();
  unsigned int block_size;
  if (-1 == sscanf(sig, "%u:", &block_size))
    return false;

  // Move past the blocksize
  sig = strchr(sig,':');
  if (!sig)
    return false;

  // Move past the first colon and Look for the second colon
  ++sig;
  sig = strchr(sig,':');
  if (!sig)
    return false;

  // Finally, a valid signature does *not* have a filename at the end of it
  sig = strchr(sig,',');
  if (sig)
    return false;

  return true;
}
*/

Filedata::Filedata(const TCHAR *fn,
		   const char * sig,
		   const char * match_file) {

  if (NULL == sig)
    throw std::bad_alloc();

  // We don't test fn as it may be NULL, such as when reading in lines
  // from a signature file. In that case we get the filename from
  // the signature itself.
  if (fn)
    m_filename = _tcsdup(fn);
  else
    m_filename = NULL;

  m_signature = strdup(sig);
  m_cluster  = NULL;

  if (NULL == match_file)
    m_has_match_file = false;
  else {
    m_has_match_file = true;
    m_match_file = strdup(match_file);
  }

  if (parse_substrings(sig))
    throw std::bad_alloc();

}

bool Filedata::parse_substrings(const char *sig) {

  char *sig1, *sig2, *filename;
  size_t len;

  // Now comes the fun part, separating out s1 and s2.
  // Each valid line has the format:
  // 123:abcdeff:ghijlmno:"FILENAME"
  // Move past the block size prefix to the first signature

  sig1 = strchr(sig, ':');
  if (not sig1)
    return true;

  // Move past the colon
  ++sig1;

  // Find the next colon, which is the end of the first signature
  sig2 = strchr(sig1, ':');
  if (not sig2)
    return true;

  len = sig2 - sig1;
  m_sig1 = (char *)malloc(1 + (len * sizeof(char)));
  if (NULL == m_sig1)
    return true;

  strncpy(m_sig1, sig1, len);

  // Move past the colon
  ++sig2;

  // Find the start of the filename
  filename = strchr(sig2, ',');

  // If there's no filename, that's ok, just use the end of the string
  if (not filename)
    filename = sig2 + strlen(sig2);

  len = filename - sig2;
  m_sig2 = (char *)malloc(1 + (len * sizeof(char)));
  if (NULL == m_sig2)
    return true;
  strncpy(m_sig2, sig2, len);

  // If we have a filename already, we don't need one now
  if (m_filename)
    return false;

  // But if we need one, and don't have one here, we fail.
  if (not filename)
    return true;

  // Okay! So there is a filename. It should be immediately after the
  // first comma and enclosed in quotation marks.
  // Advance past the comma and quotation mark.
  filename += 2;

  // Look for the second quotation mark, which should be at the end
  // of the string.
  char * stop = strrchr(filename, '"');
  if (stop != filename + strlen(filename) - 1)
    return true;

  char * tmp = (char *)malloc((strlen(filename) + 1) * sizeof(char));
  if (NULL == tmp)
    return true;

  // Don't copy over the last quoation mark.
  strncpy(tmp, filename, strlen(filename) - 1);

  // RBF - Unescape quotation marks in the filename
  // We must look for ESCAPED quotes \"
  //  while ((stop = strchr('"', tmp)) != NULL) {
  // memmove(tmp + stop, m_filename

#ifdef _WIN32
  // RBF - MODIFY THIS CODE

  // On Win32 we have to do a kludgy cast from ordinary char
  // values to the TCHAR values we use internally. Because we may have
  // reset the string length, get it again.
  // The extra +1 is for the terminating newline
  char * tmp2 = strdup(tmp.c_str());
  size_t i, sz = strlen(tmp2);
  m_filename = (TCHAR *)malloc(sizeof(TCHAR) * (sz + 1));
  if (NULL == m_filename)
    throw std::bad_alloc();

  for (i = 0 ; i < sz ; i++)
    m_filename[i] = (TCHAR)(tmp2[i]);
  m_filename[i] = 0;
# else
  m_filename = strdup(tmp);
#endif

  free(tmp);
  return false;
}


void Filedata::clear_cluster(void)
{
  if (NULL == m_cluster)
    return;

  // We don't want to call the destructors on the individual elements
  // so we have to clear the set first.
  m_cluster->clear();
  m_cluster = NULL;
}

std::ostream& operator<<(std::ostream& o, const Filedata& f) {
  return o << f.get_signature() << "," << f.get_filename() << ",";
}


bool operator==(const Filedata& a, const Filedata& b) {
  if (a.get_signature() != b.get_signature())
    return false;
  if (a.has_match_file() and not b.has_match_file())
    return false;
  if (not a.has_match_file() and b.has_match_file())
    return false;
  if (a.has_match_file() and b.has_match_file()) {
    if (a.get_match_file() != b.get_match_file())
      return false;
  }

  return true;
}

