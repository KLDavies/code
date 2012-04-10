// $Id$

#include <vector>
#include <iostream>
#include <map>
#include <set>

#include <stdlib.h>
#include <assert.h>

#include "helpers.h"

using namespace std;

#define HEADER "ssdeep,1.1--blocksize:hash:hash,filename"
#define MAX_STR_LEN 2048
#define MIN_SUBSTR_LEN 7

typedef struct 
{
  uint64_t id;

  uint16_t blocksize;
  // Holds signature equal to blocksize
  std::string s1;
  // Holds signature equal to blocksize * 2
  std::string s2;
  
  std::string filename;

  // File where this known file came from
  std::string knownfile_name;
} filedata_t;


void display_filedata(const filedata_t f)
{
  cout << "Filename: " << f.filename << " from " << f.knownfile_name << endl;
  cout << f.blocksize << " " << f.s1 << " " << f.s2 << endl;
}


/// We use a set to avoid duplicates
typedef map<std::string,set<filedata_t *> > index_t;


typedef struct
{
  uint64_t next_id;

  vector<filedata_t *> all_files;
  char buffer[MAX_STR_LEN];

  // RBF - Eventually we will need a map of these by blocksize
  index_t index;
} state_t;


bool add_indexes(state_t &s, filedata_t * f)
{
  size_t end = f->s1.size() - MIN_SUBSTR_LEN + 1;

  for (size_t pos = 0 ; pos < end ; ++pos)
  {
    std::string sub = f->s1.substr(pos,MIN_SUBSTR_LEN);

    //    cout << sub << ": ";

    index_t::iterator it = s.index.find(sub);
    if (s.index.end() == it)
    {
      //      cout << "Not found" << endl;
      set<filedata_t *> tmp;
      tmp.insert(f);
      s.index.insert(std::pair<std::string,set<filedata_t *> >(sub,tmp));
    }
    else
    {
      //      cout << "Found!" << endl;
      
      //      cout << "Size: " << it->second.size() << endl;

      it->second.insert(f);
    }
  }

  return false;
}



bool lookup(state_t&s, filedata_t f)
{
  set<uint64_t> visited;
  size_t end = f.s1.size() - MIN_SUBSTR_LEN + 1;
  for (size_t pos = 0 ; pos < end ; ++pos)
  {
    std::string sub = f.s1.substr(pos,MIN_SUBSTR_LEN);
    index_t::const_iterator it = s.index.find(sub);
    if (s.index.end() == it)
      continue;

    //    cout << "Found potential matches" << endl;
    set<filedata_t *>::const_iterator match_it;
    for (match_it = it->second.begin() ; match_it != it->second.end() ; ++match_it)
    {
      if (visited.count((*match_it)->id) != 0)
	continue;

      cout << f.filename << " may match " << (*match_it)->filename << endl;
      visited.insert((*match_it)->id);
    }

  }

  cout << endl;
  return false;
}




bool load_known_hash(state_t& s)
{
  char filename[MAX_STR_LEN];

  filedata_t * tmp = new filedata_t;
  if (NULL == tmp)
      return true;

  strncpy(filename,s.buffer,MAX_STR_LEN);
  
  find_comma_separated_string(filename,1);
  find_comma_separated_string(s.buffer,0);
  
  tmp->filename =  std::string(filename);

  size_t found;
  std::string sig = std::string(s.buffer);
  cout << sig << endl;
  found = sig.find(':');
  if (found == string::npos)
    return true;

  // Note: We modify the original buffer!
  s.buffer[found] = 0;
  tmp->blocksize = atoi(s.buffer);
  //  cout << "blocksize = " << tmp->blocksize << endl;

  //  cout << "Found colon at " << found << endl;

  size_t start = found + 1;

  found = sig.find(":",found+1);
  if (found == string::npos)
    return true;

  tmp->s1 = sig.substr(start,found - start);
  //  cout << tmp->s1 << endl;

  tmp->s2 = sig.substr(found+1);
  //  cout << tmp->s2 << endl;

  //  display_filedata(*tmp);
  //  cout << endl;

  tmp->id = s.next_id;
  s.next_id++;

  lookup(s,*tmp);
  
  add_indexes(s,tmp);

  s.all_files.push_back(tmp);

  return false;
}



bool load_known_hashes(state_t& s, FILE * handle)
{
  // The first line was the header
  uint64_t line_number = 1;

  while (!feof(handle))
  {
    if (NULL == fgets(s.buffer,MAX_STR_LEN,handle))
    {
      if (feof(handle))
	return false;
      else
      {
	// RBF - Error handling
	return true;
      }
    }

    chop_line(s.buffer);

    load_known_hash(s);

    //    cout << s.buffer << endl;
  }

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

  if (strncasecmp(s.buffer,HEADER,MAX_STR_LEN))
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

  load_known_file(s,"sample.txt");

  //all_substrings(std::string("abcdefghijklmnopqrstuvwxyz"),7);

  return EXIT_SUCCESS;
}
