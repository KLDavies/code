// ssdeep
// (C) Copyright 2012 ManTech International Corporation
//
// $Id$
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA


#include "ssdeep.h"

// The longest line we should encounter when reading files of known hashes 
#define MAX_STR_LEN  2048

#define MIN_SUBSTR_LEN 7

// ------------------------------------------------------------------
// SIGNATURE FILE FUNCTIONS
// ------------------------------------------------------------------

/// Open a file of known hashes and determine if it's valid
///
/// @param s State variable
/// @param handle Receives pointer to open file RBF
/// @param fn filename to open
/// 
/// @return RBF eturns true on errror, false on success.
static
FILE * sig_file_open(state *s, const char * fn)
{
  char buffer[MAX_STR_LEN];

  if (NULL == fn)
    return NULL;

  FILE * handle = fopen(fn,"rb");
  if (NULL == handle)
  {
    if ( ! (MODE(mode_silent)) )
      perror(fn);
    return NULL;
  }

  // The first line should be the header. We don't need to chop it
  // as we're only comparing it to the length of the known header.
  if (NULL == fgets(buffer,MAX_STR_LEN,handle))
  {
    if ( ! (MODE(mode_silent)) )
      perror(fn);
    fclose(handle);
    return NULL;
  }

  if (strncmp(buffer,SSDEEPV1_0_HEADER,strlen(SSDEEPV1_0_HEADER)) &&
      strncmp(buffer,SSDEEPV1_1_HEADER,strlen(SSDEEPV1_1_HEADER)))
  {
    if ( ! (MODE(mode_silent)) )
      print_error(s,"%s: Invalid file header.", fn);
    fclose(handle);
    return NULL;
  }

  return handle;
}


bool str_to_filedata(state *s, const char * buffer, filedata_t *f)
{
  // Set the id first, so that if something goes wrong, we don't
  // reuse the id number.
  f->id = s->next_match_id;
  s->next_match_id++;

  // RBF - Do we need to remove the filename from the signature?
  f->signature = std::string(buffer);

  // Find the blocksize
  size_t found;
  found = f->signature.find(':');
  if (found == std::string::npos)
    return true;
  // RBF - Wider bitwidth?
  f->blocksize = atoi(f->signature.substr(0,found).c_str());
  //  cout << "blocksize = " << f->blocksize << endl;

  // Find the two signature components
  size_t start = found + 1;
  found = f->signature.find(":",found+1);
  if (found == std::string::npos)
    return true;

  f->s1 = f->signature.substr(start,found - start);

  start = found+1;
  found = f->signature.find(",",found+1);
  if (found == std::string::npos)
    return true;

  f->s2 = f->signature.substr(start, found - start);

  // RBF - Remove quotes from the ends of strings

#ifndef _WIN32
  f->filename = strdup(f->signature.substr(found + 1).c_str());
  remove_escaped_quotes(f->filename);
#else
  char * tmp = f->signature.substr(found + 1).c_str();
  remove_escaped_quotes(tmp);
  // On Win32 we have to do a kludgy cast from ordinary char 
  // values to the TCHAR values we use internally. Because we may have
  // reset the string length, get it again.
  size_t i, sz = strlen(tmp);
  f->filename = (char *)malloc(sizeof(char) * sz);
  // RBF - error checking
  for (i = 0 ; i < sz ; i++)
    f->filename[i] = (TCHAR)(tmp[i]);
  f->filename[i] = 0;
#endif

  return false;
}


/// Read the next entry in a file of known hashes
///
/// @param s State variable (RBF - Do we need this?)
/// @param handle File handle to read from
/// @param fn Filename of known hashes
/// @param f Structure where to store read data
///
/// @return Returns true if there is no entry to read or on error. Otherwise, false.
static
bool sig_file_next(state *s, FILE * handle, char * fn, filedata_t * f)
{
  if (NULL == s || NULL == fn || NULL == f || NULL == handle)
    return true;

  char buffer[MAX_STR_LEN];
  memset(buffer,0,MAX_STR_LEN);
  if (NULL == fgets(buffer,MAX_STR_LEN,handle))
    return true;

  chop_line(buffer);
  
  f->match_file = std::string(fn);

  return str_to_filedata(s,buffer,f);
}


bool sig_file_close(FILE * handle)
{
  if (handle != NULL) 
    fclose(handle);
  
  return false;
}



// ------------------------------------------------------------------
// MATCHING FUNCTIONS
// ------------------------------------------------------------------


void handle_match(state *s, const char * fn, const char * match_file, filedata_t * match, int score)
{
  if (s->mode & mode_csv)
  {
    printf("\"");
    display_filename(stdout,fn,TRUE);
    printf("\",\"");
    display_filename(stdout,match->filename,TRUE);
    print_status("\",%"PRIu32, score);
  }
  else
  {
    if (strlen(match_file) > 0)
      printf ("%s:", match_file);
    display_filename(stdout,fn,FALSE);
    printf(" matches ");
    if (strlen(match->match_file.c_str()) > 0)
      printf ("%s:", match->match_file.c_str());
    display_filename(stdout,match->filename,FALSE);
    print_status(" (%"PRIu32")", score);
  }
}



// Match the file named fn with the hash sum against the set of knowns
// Display any matches. 
/// @return Returns false if there are no matches, true if at least one match
/// @param s State variable
/// @param match_file Filename where we got the hash of the unknown file.
///                   May be NULL.
/// @param fn Filename of the unknown file we are comparing
/// @param sum Fuzzy hash of the unknown file we are comparing
bool match_compare(state *s, 
		   const char * match_file, 
		   TCHAR *fn, 
		   const char *sum)
{
  if (NULL == s || NULL == fn || NULL == sum)
    fatal_error("%s: Null values passed into match_compare", __progname);

  bool status = false;
  std::set<uint64_t> visited;
  
  std::string sig = std::string(sum);

  size_t end = 0;
  if (sig.size() >= MIN_SUBSTR_LEN)
    end = sig.size() - MIN_SUBSTR_LEN + 1;

  // RBF - Do we need to do anything for match_pretty here? 
  // We did in the old version

  for (size_t pos = 0 ; pos < end ; ++pos)
  {
    std::string sub = sig.substr(pos,MIN_SUBSTR_LEN);
    index_t::const_iterator it = s->index.find(sub);
    if (s->index.end() == it)
      continue;

    std::set<filedata_t *>::const_iterator match_it;
    for (match_it = it->second.begin() ; 
	 match_it != it->second.end() ; 
	 ++match_it)
    {
      // If we've compared these two ids before, skip them.
      if (visited.count((*match_it)->id) != 0)
	continue;
      
      int score =  fuzzy_compare(sum, (*match_it)->signature.c_str());
      if (-1 == score)
      {
	print_error(s, "%s: Bad hashes in comparison", __progname);
      }
      else
      {
	if (score > s->threshold || MODE(mode_display_all))
	{
	  handle_match(s,fn,match_file,(*match_it),score);
	  status = true;
	}
      }

      visited.insert((*match_it)->id);
    }
  }
  
  return status;
}

  


  /*
// Match the file named fn with the hash sum against the set of knowns
// Display any matches. 
// Return FALSE is there are no matches, TRUE if at least one match
/// @param s State variable
/// @param match_file Filename where we got the hash of the unknown file.
///                   May be NULL.
/// @param fn Filename of the unknown file we are comparing
/// @param sum Fuzzy hash of the unknown file we are comparing
int match_compare(state *s, char * match_file, const TCHAR *fn, const char *sum)
{
  if (NULL == s || NULL == fn || NULL == sum)
    fatal_error("%s: Null values passed into match_compare", __progname);

  size_t fn_len  = _tcslen(fn);
  size_t sum_len = strlen(sum);

  int status = FALSE;
  int score;
  lsh_node *tmp = s->known_hashes->top;

  while (tmp != NULL)
  {
    if (s->mode & mode_match_pretty)
    {
      // Prevent printing the redundant "A matches A"
      if (!(_tcsncmp(fn,tmp->fn,MAX(fn_len,_tcslen(tmp->fn)))) &&
	  !(strncmp(sum,tmp->hash,MAX(sum_len,strlen(tmp->hash)))))
      {
	// Unless these results from different matching files (such as
	// what happens in sigcompare mode). That being said, we have to
	// be careful to avoid NULL values such as when working in 
	// normal pretty print mode.
	if (NULL == match_file || NULL == tmp->match_file ||
	    (!(strncmp(match_file, tmp->match_file, MAX(strlen(match_file),strlen(tmp->match_file))))))
	{
	  tmp = tmp->next;
	  continue;
	}
      }
    }

    score = fuzzy_compare(sum,tmp->hash);
    if (-1 == score)
    {
      print_error(s, "%s: Bad hashes in comparison", __progname);
    }
    else
    {
      if (score > s->threshold || MODE(mode_display_all))
      {
	if (s->mode & mode_csv)
	{
	  printf("\"");
	  display_filename(stdout,fn,TRUE);
	  printf("\",\"");
	  display_filename(stdout,tmp->fn,TRUE);
	  print_status("\",%"PRIu32, score);
	}
	else
	{
	  if (match_file != NULL)
	    printf ("%s:", match_file);
	  display_filename(stdout,fn,FALSE);
	  printf(" matches ");
	  if (tmp->match_file != NULL)
	    printf ("%s:", tmp->match_file);
	  display_filename(stdout,tmp->fn,FALSE);
	  print_status(" (%"PRIu32")", score);
	}
      
	// We don't return right away as this file could match more than
	// one signature. 
	status = TRUE;
      }
    }
    
    tmp = tmp->next;
  }

  return status;
}
  */


bool match_pretty(state *s)
{
  if (NULL == s)
    return true;

  // Walk the index
  std::vector<filedata_t *>::iterator it;
  for (it = s->all_files.begin() ; it != s->all_files.end() ; ++it)
  {
    if (match_compare(s,
		      (*it)->match_file.c_str(),
		      (*it)->filename,
		      (*it)->signature.c_str()))
      print_status("");
  }


  /*
  while (tmp != NULL)
  {
    if (match_compare(s,tmp->match_file,tmp->fn,tmp->hash))
      print_status("");

    tmp = tmp->next;
  }
  */

  return false;
}




  
/// Add a fuzzy signature to the index
///
/// @param s State variable
/// @param f File data for the file to add
/// @param sig Signature component to add. Should be f.s1 or f.s2
bool add_known_sig(state *s, filedata_t *f, std::string sig)
{
  // RBF - What happens when sig.size < MIN_SUBSTR_LEN?? Can we match at all?
  size_t end = 0;
  if (sig.size() > MIN_SUBSTR_LEN)  
    end = sig.size() - MIN_SUBSTR_LEN + 1;

  for (size_t pos = 0 ; pos < end ; ++pos)
  {
    std::string substring = sig.substr(pos,MIN_SUBSTR_LEN);
    index_t::iterator it = s->index.find(substring);
    if (s->index.end() == it)
    {
      // This substring is not in the index. Add it and a pointer
      // to the current file.
      std::set<filedata_t *> tmp;
      tmp.insert(f);
      s->index.insert(std::pair<std::string,std::set<filedata_t *> >(substring,tmp));
    }
    else
    {
      // This substring is in the index. Add a pointer to the current
      // file to the existing value.
      it->second.insert(f);
    }
  }

  return false;
}


/// Add a file to the set of known files
///
/// @param s State variable
/// @param f File data for the file to add
bool add_known_file(state *s, filedata_t *f)
{
  add_known_sig(s,f,f->s1);
  add_known_sig(s,f,f->s2);

  s->all_files.push_back(f);

  return false;
}


// RBF - There has to be a better way to do this
bool match_add(state *s, char * match_file, TCHAR *fn, char *hash)
{
  filedata_t * f = new filedata_t;

  str_to_filedata(s,hash,f);
  f->filename = strdup(fn);
  f->match_file = std::string(match_file);

  add_known_file(s,f);

  return false;
}




bool match_load(state *s, char *fn)
{
  if (NULL == s || NULL == fn)
    return true;

  bool status = false;
  FILE * handle = sig_file_open(s,fn);
  if (NULL == handle)
    return true;

  filedata_t * f = new filedata_t;

  uint64_t line_number = 1;

  while ( ! sig_file_next(s,handle,fn,f) )
  {
    if (add_known_file(s,f))
    {
      print_error(s,"%s: unable to insert hash", fn);
      status = true;
      break;
    }

    f = new filedata_t;

    ++line_number;
  }

  sig_file_close(handle);

  return status;
}


bool match_compare_unknown(state *s, char * fn)
{ 
  if (NULL == s || NULL == fn)
    return true;

  FILE * handle = sig_file_open(s,fn);
  if (NULL == handle)
    return true;

  filedata_t f;
  
  while ( ! sig_file_next(s,handle,fn,&f))
  {
    match_compare(s,fn,f.filename,f.signature.c_str());
  }

  sig_file_close(handle);

  return FALSE;
}











// RBF - Set the match file!
/*
bool load_known_hash(state * s, filedata_t * f)
{
  char buffer[MAX_STR_LEN];

  if (NULL == f)
    return true;

  // Set the id first, so that if something goes wrong, we don't
  // reuse the id number.
  f->id = s->next_match_id;
  s->next_match_id++;

  f->signature = std::string(buffer);

  // Find the blocksize
  size_t found;
  found = f->signature.find(':');
  if (found == std::string::npos)
    return true;

  // RBF - Wider bitwidth?
  f->blocksize = atoi(f->signature.substr(0,found).c_str());
  //  cout << "blocksize = " << f->blocksize << endl;

  size_t start = found + 1;

  found = f->signature.find(":",found+1);
  if (found == std::string::npos)
    return true;

  f->s1 = f->signature.substr(start,found - start);

  start = found+1;
  found = f->signature.find(",",found+1);
  if (found == std::string::npos)
    return true;

  f->s2 = f->signature.substr(start, found - start);

  // RBF - Need to strip quotes from filename
  f->filename = f->signature.substr(found + 1);

  return false;
}


int match_insert
{
  filedata_t * f = new filedata_t;
  if (NULL == f)
  {
    // RBF - Error handling
    // cerr << "Out of memory!" << endl;
    return true;
  }

  load_

  // Does this new file match any of the existing files?
  // RBF - Handle this functionality?
  //  lookup(s,*f);
  
  add_indexes(s,f,f->s1);
  add_indexes(s,f,f->s2);

  // RBF - Do we need a non-indexed vector of all of the files? 
  //s.all_files.push_back(f);
  */







  /*
/// Loads known fuzzy hashes from the disk and stores them in the state
///
/// @param s State variable
/// @param handle Open file handle to the known hashes. Should be pointing
/// to the first hash in the file. (That is, not the header)
///
/// @return Returns false on success, true on error.
bool load_known_hashes(state *s, FILE * handle)
{
  char buffer[MAX_STR_LEN];

  // The first line was the header
  uint64_t line_number = 1;

  while (!feof(handle))
  {
    if (NULL == fgets(buffer,MAX_STR_LEN,handle))
    {
      // There is no error if we hit the end of the file.
      return ( ! feof(handle) );
    }

    chop_line(buffer);

    filedata_t * f = new filedata_t;
    if (NULL == f)
    {
      // RBF - Error handling
      // cerr << "Out of memory!" << endl;
      return true;
    }

    if (load_known_hash(s,buffer,f))
    {
      // RBF - Error handling
      //cerr << "Invalid hash in line " << line_number << endl;
    }

    

    ++line_number;
  }

  //  cerr << "Index size = " << s.index.size() << endl;
  return false;
}
  */











/*


int combine_clusters(state *s, lsh_node *a, lsh_node *b, uint64_t next_cluster)
{
  // We are guaranteed that both a->cluster and b->cluster are not zero.
  // One or the other maybe, but not both.
  if (0 == b->cluster)
  {
    // RBF - Debugging
    printf ("Adding to a cluster %"PRIu64"\n", a->cluster);
    b->cluster = a->cluster;
    return FALSE;
  }
  if (0 == a->cluster)
  {
    // RBF - Debugging
    printf ("Adding to b cluster %"PRIu64"\n", b->cluster);
    a->cluster = b->cluster;
    return FALSE;
  }

  // RBF - Debugging
  printf ("Combining clusters %"PRIu64" and %"PRIu64"\n", a->cluster, b->cluster);
  uint64_t dest = a->cluster;
  uint64_t src = b->cluster;
  lsh_node * tmp = s->known_hashes->top;
  while (tmp != NULL)
  {
    if (tmp->cluster == src)
      tmp->cluster = dest;
  }

  return FALSE;
}


int display_clusters(state *s)
{
  if (NULL == s)
    return TRUE;

  uint64_t next_cluster = 0;

  // Iterate through all files
  lsh_node *a = s->known_hashes->top;
  while (a != NULL)
  {
    lsh_node *b = a->next;
    while (b != NULL)
    {
      // If these two are already in the same cluster, we don't
      // need to do anything. But we should compare if one of them
      // is unassigned.
      if (a->cluster != b->cluster || a->cluster == 0)
      {
	int score = fuzzy_compare(a->hash, b->hash);
	if (-1 == score)
	{
	  // RBF - Error handling
	  b = b->next;
	  continue;
	}
	
	if (score > s->threshold)
	{
	  printf ("Found match of %s and %s %d\n", a->fn, b->fn, score);
	  if (0 == a->cluster && 0 == b->cluster)
	  {
	    // Neither file is assigned so far. Easy! Make a new cluster
	    ++next_cluster;
	    a->cluster = next_cluster;
	    b->cluster = next_cluster;
	  }
	  else
	  {
	    // Combine existing clusters
	    combine_clusters(s,a,b,next_cluster);
	  }
	}
      }

      b = b->next;
    }

    a = a->next;
  }

  return FALSE;
}
*/
