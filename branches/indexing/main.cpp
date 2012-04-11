// $Id$

#include <vector>
#include <iostream>
#include <map>
#include <set>
#include <algorithm>

#include <stdlib.h>
#include <assert.h>

#include <fuzzy.h>

#include "helpers.h"

using namespace std;

#define SSDEEP_HEADER_11 "ssdeep,1.1--blocksize:hash:hash,filename"
#define MAX_STR_LEN 2048
#define MIN_SUBSTR_LEN 7

typedef struct 
{
  uint64_t id;

  /// Original signature in the form [blocksize]:[sig1]:[sig2]
  std::string signature;
  
  /// RBF - Does this need to be a larger bitwidth?
  uint16_t blocksize;

  /// Holds signature equal to blocksize
  std::string s1;
  /// Holds signature equal to blocksize * 2
  std::string s2;

  std::string filename;

  /// File of hashes where we got this known file from.
  std::string knownfile_name;
} filedata_t;

/// We use a set to avoid duplicates
typedef map<std::string,set<filedata_t *> > index_t;

typedef struct
{
  uint64_t next_id;

  vector<filedata_t *> all_files;
  char buffer[MAX_STR_LEN];

  // RBF - Eventually we will need a map of these by blocksize
  // RBF - Do we?
  index_t index;
} state_t;



std::ostream& operator<<(std::ostream& o, const filedata_t f)
{
  o << f.blocksize << ":" << f.s1 << ":" << f.s2 << "," << f.filename;
  return o;
}

void display_filedata(const filedata_t f)
{
  cout << "Filename: " << f.filename << " from " << f.knownfile_name << endl;
  cout << f.blocksize << " " << f.s1 << " " << f.s2 << endl;
}



bool add_indexes(state_t &s, filedata_t * f, const std::string sig)
{
  // RBF - What happens when sig.size < MIN_SUBSTR_LEN?? Can we match at all?
  size_t end = 0;
  if (sig.size() > MIN_SUBSTR_LEN)  
    end = sig.size() - MIN_SUBSTR_LEN + 1;

  for (size_t pos = 0 ; pos < end ; ++pos)
  {
    std::string substring = sig.substr(pos,MIN_SUBSTR_LEN);
    index_t::iterator it = s.index.find(substring);
    if (s.index.end() == it)
    {
      // This substring is not in the index. Add it and a pointer
      // to the current file.
      set<filedata_t *> tmp;
      tmp.insert(f);
      s.index.insert(std::pair<std::string,set<filedata_t *> >(substring,tmp));
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


bool lookup_sig(state_t& s, 
		filedata_t f, 
		std::string sig, 
		std::set<uint64_t> visited)
{
  size_t end = 0;
  if (sig.size() >= MIN_SUBSTR_LEN)
    end = sig.size() - MIN_SUBSTR_LEN + 1;

  for (size_t pos = 0 ; pos < end ; ++pos)
  {
    std::string sub = sig.substr(pos,MIN_SUBSTR_LEN);
    index_t::const_iterator it = s.index.find(sub);
    if (s.index.end() == it)
      continue;

    set<filedata_t *>::const_iterator match_it;
    for (match_it = it->second.begin() ; 
	 match_it != it->second.end() ; 
	 ++match_it)
    {
      // If we've compared these two ids before, skip them.
      if (visited.count((*match_it)->id) != 0)
	continue;
      
      int score =  fuzzy_compare(f.signature.c_str(),
				 (*match_it)->signature.c_str());
      if (score > 0)
      {
	cout << f.filename << " matches " << (*match_it)->filename <<
	  "(" << score << ")" << endl;
      }

      visited.insert((*match_it)->id);
    }
  }

  return false;
}



bool lookup(state_t&s, filedata_t f)
{
  set<uint64_t> visited;

  lookup_sig(s,f,f.s1,visited);
  lookup_sig(s,f,f.s2,visited);

  return false;
}




bool load_known_hash(state_t& s)
{
  filedata_t * f = new filedata_t;
  if (NULL == f)
  {
    cerr << "Out of memory!" << endl;
    return true;
  }

  // Set the id first, so that if something goes wrong, we don't
  // reuse the id number.
  f->id = s.next_id;
  s.next_id++;

  f->signature = std::string(s.buffer);

  // Find the blocksize
  size_t found;
  found = f->signature.find(':');
  if (found == string::npos)
    return true;

  f->blocksize = atoi(f->signature.substr(0,found).c_str());
  //  cout << "blocksize = " << f->blocksize << endl;

  size_t start = found + 1;

  found = f->signature.find(":",found+1);
  if (found == string::npos)
    return true;

  f->s1 = f->signature.substr(start,found - start);

  start = found+1;
  found = f->signature.find(",",found+1);
  if (found == string::npos)
    return true;

  f->s2 = f->signature.substr(start, found - start);

  // RBF - Need to strip quotes from filename
  f->filename = f->signature.substr(found + 1);

  // Does this new file match any of the existing files?
  lookup(s,*f);
  
  add_indexes(s,f,f->s1);
  add_indexes(s,f,f->s2);

  // RBF - Do we need a non-indexed vector of all of the files? 
  s.all_files.push_back(f);

  return false;
}



/// Loads known fuzzy hashes from the disk and stores them in the state
///
/// @param s State variable
/// @param handle Open file handle to the known hashes. Should be pointing
/// to the first hash in the file. (That is, not the header)
///
/// @return Returns false on success, true on error.
bool load_known_hashes(state_t& s, FILE * handle)
{
  // The first line was the header
  uint64_t line_number = 1;

  while (!feof(handle))
  {
    if (NULL == fgets(s.buffer,MAX_STR_LEN,handle))
    {
      cerr << "Index size = " << s.index.size() << endl;

      // There is no error if we hit the end of the file.
      return ( ! feof(handle) );
    }

    chop_line(s.buffer);
    if (load_known_hash(s))
      cerr << "Invalid hash in line " << line_number << endl;

    ++line_number;
  }

  cerr << "Index size = " << s.index.size() << endl;
  return false;
}


bool load_known_file(state_t &s, const char *fn)
{
  FILE * handle = fopen(fn,"rb");
  if (NULL == handle)
  {
    perror(fn);
    return true;
  }

  fgets(s.buffer, MAX_STR_LEN, handle);
  chop_line(s.buffer);

  if (strncasecmp(s.buffer,SSDEEP_HEADER_11,MAX_STR_LEN))
  {
    cerr << "Invalid header, skipping" << endl;
    fclose(handle);
    return true;
  }
  
  bool status = load_known_hashes(s,handle);

  fclose(handle);
  return status;
}



void initialize_state(state_t& s)
{
  s.next_id = 0;
}


int main(int argc, char **argv)
{
  state_t s;
  initialize_state(s);

  for (int i = 1 ; i < argc ; ++i)
  {
    load_known_file(s,argv[i]);
  }

  return EXIT_SUCCESS;
}
