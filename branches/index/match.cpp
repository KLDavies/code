// ssdeep
// (C) Copyright 2012 Kyrus
// (C) Copyright 2013 Facebook
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

#include "match.h"

// The longest line we should encounter when reading files of known hashes
#define MAX_STR_LEN  2048

#define MIN_SUBSTR_LEN 7

static const std::string base64_chars =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  "abcdefghijklmnopqrstuvwxyz"
  "0123456789+/";

uint32_t base64_decode(char *address, size_t len)
{
  uint8_t data[4] = {0}, b[4] = {0};
  size_t pos;

  // RBF - There has to be a faster way to do this, but this works.
  for (pos = 0 ; pos < len ; ++pos)
    b[pos] = base64_chars.find(address[pos]);

  data[0] = (b[0] << 2) | ((b[1] & 0x30) >> 4);
  data[1] = ((b[1] & 0xf) << 4) | ((b[2] & 0x3c) >> 2);
  data[2] = ((b[2] & 0x3) << 6);
  if (len == 4)
    data[2] |= b[3];

  return (data[2] << 16) | (data[1] << 8) | data[0];
}

bool operator<(const bucket_t &a, const bucket_t &b) {
  return a.ekey < b.ekey;
}

bool add_single_ngram(state *s, char * ngram, Filedata * f) {
  char address_str[5] = {0}, ekey_str[5] = {0};
  uint32_t address = 0, ekey = 0;
  bucket_t * b;

  if (NULL == s or NULL == ngram or NULL == f)
    return true;

  memcpy(address_str, ngram, 3);
  // RBF - Is this the way to do it?
  memcpy(ekey_str, ngram+3, 4);
  //  printf ("%s -> %s:%s\n", ngram, address_str, ekey_str);

  address = base64_decode(address_str,3);
  ekey = base64_decode(ekey_str, 4);
  //  printf ("Address: 0x%"PRIx32"   ekey: 0x%"PRIx32"\n", address, ekey);

  b = (bucket_t *)malloc(sizeof(bucket_t));
  if (NULL == b)
    return true;

  b->ekey = ekey;
  b->filedata = f;

  //  printf ("%lu\n", s->known_buckets[address].size());
  s->known_buckets[address].insert(b);
  //  printf ("%lu\n", s->known_buckets[address].size());

  return false;
}

bool add_ngrams(state *s, const char *sig, Filedata *f) {
  if (NULL == s or NULL == sig or NULL == f)
    return true;

  size_t pos, len=strlen(sig) - (MIN_SUBSTR_LEN-1);
  char ngram[MIN_SUBSTR_LEN+1] = {0};

  // If we get a short signature, set it to a default ngram:
  if (strlen(sig) < MIN_SUBSTR_LEN) {
    memset(ngram, 'A', MIN_SUBSTR_LEN);
    add_single_ngram(s, ngram, f);
  } else {
    for (pos = 0; pos < len ; ++pos) {
      memcpy(ngram, sig+pos, MIN_SUBSTR_LEN);
      add_single_ngram(s, ngram, f);
    }
  }

  return false;
}


bool add_to_index(state *s, Filedata *f) {
  if (NULL == s or NULL == f)
    return true;

  add_ngrams(s, f->get_sig1(), f);
  add_ngrams(s, f->get_sig2(), f);

  return false;
}

// ------------------------------------------------------------------
// SIGNATURE FILE FUNCTIONS
// ------------------------------------------------------------------

/// Open a file of known hashes and determine if it's valid
///
/// @param s State variable
/// @param fn filename to open
///
/// @return Returns false success, true on error
bool sig_file_open(state *s, const char * fn)
{
  char buffer[MAX_STR_LEN];

  if (NULL == s or NULL == fn)
    return true;

  s->known_handle = fopen(fn,"rb");
  if (NULL == s->known_handle) {
    if ( ! (MODE(mode_silent)) )
      perror(fn);
    return true;
  }

  // The first line of the file should contain a valid ssdeep header.
  if (NULL == fgets(buffer,MAX_STR_LEN,s->known_handle)) {
    if ( ! (MODE(mode_silent)) )
      perror(fn);
    fclose(s->known_handle);
    return true;
  }

  chop_line(buffer);

  if (strncmp(buffer,SSDEEPV1_0_HEADER,MAX_STR_LEN) and
      strncmp(buffer,SSDEEPV1_1_HEADER,MAX_STR_LEN)) {
    if ( ! (MODE(mode_silent)) )
      print_error(s,"%s: Invalid file header.", fn);
    fclose(s->known_handle);
    return true;
  }

  // We've now read the first line
  s->line_number = 1;
  s->known_fn = strdup(fn);

  return false;
}

/// @brief Read the next entry in a file of known hashes and convert
/// it to a Filedata
///
/// @param s State variable
/// @param fn filename where this entry came from
///
/// @return Returns a pointer to a valid Filedata object or null on error.
Filedata * sig_file_next(state *s, const char * fn) {
  if (NULL == s or NULL == fn)
    return NULL;

  char buffer[MAX_STR_LEN] = {0};
  if (NULL == fgets(buffer, MAX_STR_LEN, s->known_handle))
    return NULL;

  s->line_number++;
  chop_line(buffer);

  Filedata *f;
  try {
    f = new Filedata(NULL, buffer, fn);
  } catch (std::bad_alloc) {
    return NULL;
  }

  return f;
}

bool sig_file_close(state *s) {
  if (NULL == s)
    return true;

  if (s->known_handle != NULL)
    return true;

  if (fclose(s->known_handle))
    return true;

  free(s->known_fn);

  return false;
}

bool sig_file_end(state *s) {
  return (feof(s->known_handle));
}



// ------------------------------------------------------------------
// MATCHING FUNCTIONS
// ------------------------------------------------------------------

void display_clusters(const state *s)
{
  if (NULL == s)
    return;

  std::set<std::set<Filedata *> *>::const_iterator it;
  for (it = s->all_clusters.begin(); it != s->all_clusters.end() ; ++it)
  {
    print_status("** Cluster size %u", (*it)->size());
    std::set<Filedata *>::const_iterator cit;
    for (cit = (*it)->begin() ; cit != (*it)->end() ; ++cit)
    {
      display_filename(stdout,(*cit)->get_filename(),FALSE);
      print_status("");
    }

    print_status("");
  }
}


void cluster_add(Filedata * dest, Filedata * src)
{
  dest->get_cluster()->insert(src);
  src->set_cluster(dest->get_cluster());
}


void cluster_join(state *s, Filedata * a, Filedata * b)
{
  // If these items are already in the same cluster there is nothing to do
  if (a->get_cluster() == b->get_cluster())
    return;

  Filedata * dest, * src;
  // Combine the smaller cluster into the larger cluster for speed
  // (fewer items to move)
  if (a->get_cluster()->size() > b->get_cluster()->size())
  {
    dest = a;
    src  = b;
  }
  else
  {
    dest = b;
    src  = a;
  }

  // Add members of src to dest
  std::set<Filedata *>::const_iterator it;
  for (it =  src->get_cluster()->begin() ;
       it != src->get_cluster()->end() ;
       ++it)
  {
    dest->get_cluster()->insert(*it);
  }

  // Remove the old cluster
  s->all_clusters.erase(src->get_cluster());
  // This call sets the cluster to NULL. Do not access the src
  // cluster after this call!
  src->clear_cluster();

  src->set_cluster(dest->get_cluster());
}


void handle_clustering(state *s, Filedata *a, Filedata *b)
{
  bool a_has = a->has_cluster(), b_has = b->has_cluster();

  // In the easiest case, one of these has a cluster and one doesn't
  if (a_has and not b_has)
  {
    cluster_add(a, b);
    return;
  }
  if (b_has and not a_has)
  {
    cluster_add(b, a);
    return;
  }

  // Combine existing clusters
  if (a_has and b_has)
  {
    cluster_join(s, a, b);
    return;
  }

  // Create a new cluster
  std::set<Filedata *> * cluster = new std::set<Filedata *>();
  cluster->insert(a);
  cluster->insert(b);

  s->all_clusters.insert(cluster);

  a->set_cluster(cluster);
  b->set_cluster(cluster);
}



void handle_match(state *s,
		  Filedata *a,
		  Filedata *b,
		  int score)
{
  if (s->mode & mode_csv) {
    printf("\"");
    display_filename(stdout, a->get_filename(), TRUE);
    printf("\",\"");
    display_filename(stdout, b->get_filename(), TRUE);
    print_status("\",%u", score);
  }
  else if (s->mode & mode_cluster) {
    handle_clustering(s, a, b);
  } else {
    // The match file names may be empty. If so, we don't print them
    // or the colon which separates them from the filename
    if (a->has_match_file())
      printf ("%s:", a->get_match_file());
    display_filename(stdout, a->get_filename(), FALSE);
    printf (" matches ");
    if (b->has_match_file())
      printf ("%s:", b->get_match_file());
    display_filename(stdout, b->get_filename(), FALSE);
    print_status(" (%u)", score);
  }
}

bool match_compare_single_ngram(state *s,
				std::set<Filedata *> &seen,
				const char *ngram,
				Filedata *f) {

  char address_str[5] = {0}, ekey_str[5] = {0};
  uint32_t address = 0, ekey = 0;

  if (NULL == s or NULL == ngram or NULL == f)
    return true;

  memcpy(address_str, ngram, 3);
  // RBF - Is this the way to do it?
  memcpy(ekey_str, ngram+3, 4);
  //  printf ("%s -> %s:%s\n", ngram, address_str, ekey_str);

  address = base64_decode(address_str,3);
  ekey = base64_decode(ekey_str, 4);
  //  printf ("Address: 0x%"PRIx32"   ekey: 0x%"PRIx32"\n", address, ekey);

  std::set<bucket_t *> known = s->known_buckets[address];
  std::set<bucket_t *>::const_iterator it;
  bool status = false;

  for (it = known.begin() ; it != known.end() ; ++it) {
    if (((*it)->ekey != ekey) or (seen.count((*it)->filedata)))
      continue;

    // The ekey matches and we haven't seen this before. Let's compare!
    // First, remember that we've made this comparison before.

    seen.insert((*it)->filedata);

    Filedata * current = (*it)->filedata;
    size_t fn_len = _tcslen(f->get_filename());

    if (s->mode & mode_match_pretty) {
      if (!(_tcsncmp(f->get_filename(),
		     current->get_filename(),
		     std::max(fn_len, _tcslen(current->get_filename())))) and
	  (f->get_signature() == current->get_signature())) {
	// Unless these results from different matching files (such as
	// what happens in sigcompare mode). That being said, we have to
	// be careful to avoid NULL values such as when working in
	// normal pretty print mode.

	//	std::cout << *f << std::endl;
	//	std::cout << *current << std::endl;

	if (not (f->has_match_file()) or
	    f->get_match_file() == current->get_match_file())
	  continue;
      }
    }

    int score =  fuzzy_compare(f->get_signature(),
			       current->get_signature());
    if (-1 == score)
      print_error(s, "%s: Bad hashes in comparison", __progname);
    else {
      if (score > s->threshold or MODE(mode_display_all)) {
	handle_match(s, f, current, score);
	status = true;
      }
    }
  }

  return status;
}


bool match_compare_ngrams(state *s,
			  std::set<Filedata *> &seen,
			  const char * sig,
			  Filedata * f) {

  if (NULL == s or NULL == sig or NULL == f)
    return true;

  size_t pos, len=strlen(sig) - (MIN_SUBSTR_LEN-1);
  char ngram[MIN_SUBSTR_LEN+1] = {0};
  bool status = false;

  // If we get a short signature, set it to a default ngram:
  // RBF - When this happens, can we just stop now? Do these
  // RBF - signatures EVER match?
  if (strlen(sig) < MIN_SUBSTR_LEN) {
    memset(ngram, 'A', MIN_SUBSTR_LEN);
    if (match_compare_single_ngram(s, seen, ngram, f))
      status = true;
  } else {
    for (pos = 0; pos < len ; ++pos) {
      memcpy(ngram, sig + pos, MIN_SUBSTR_LEN);
      if (match_compare_single_ngram(s, seen, ngram, f))
	status = true;
    }
  }

  return status;
}

bool match_compare(state *s, Filedata *f)
{
  if (NULL == s or NULL == f)
    fatal_error("%s: Null state passed into match_compare", __progname);

  bool status = false;

  // Known files we have previously compared (and should not do so again)
  std::set<Filedata *> seen;
  if (match_compare_ngrams(s, seen, f->get_sig1(), f))
    status = true;
  if (match_compare_ngrams(s, seen, f->get_sig1(), f))
    status = true;

  return status;
}


bool find_matches_in_known(state *s)
{
  if (NULL == s)
    return true;

  // Walk the vector which contains all of the known files
  std::vector<Filedata *>::const_iterator it;
  for (it = s->all_files.begin() ; it != s->all_files.end() ; ++it)
  {
    bool status = match_compare(s,*it);
    // In pretty mode and sigcompare mode we need to display a blank
    // line after each file. In clustering mode we don't display anything
    // right now.
    if (status and not(MODE(mode_cluster)))
      print_status("");
  }

  return false;
}


bool match_add(state *s, Filedata * f) {
  if (NULL == s or NULL == f)
    return true;

  add_to_index(s, f);
  s->all_files.push_back(f);

  return false;
}


bool match_load(state *s, const char *fn) {
  if (NULL == s or NULL == fn)
    return true;

  if (sig_file_open(s, fn))
    return true;

  do {
    Filedata * f = sig_file_next(s, fn);
    if (f) {
      if (match_add(s, f)) {
	// One bad hash doesn't mean this load was a failure.
	// We don't change the return status because match_add failed.
	print_error(s, "%s: unable to insert hash", fn);
	break;
      }
    }
  } while (not sig_file_end(s));

  sig_file_close(s);

  return false;
}


bool match_compare_unknown(state *s, const char * fn) {
  if (NULL == s or NULL == fn)
    return true;

  if (sig_file_open(s,fn))
    return true;

  do {
    Filedata *f = sig_file_next(s, fn);
    if (f)
      match_compare(s, f);
  } while (not sig_file_end(s));

  sig_file_close(s);

  return false;
}

