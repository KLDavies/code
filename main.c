
/* $Id$ */

#include "ssdeep.h"

static int initialize_state(state *s)
{
  s->known_hashes = (lsh_list *)malloc(sizeof(lsh_list));
  if (s->known_hashes == NULL)
    return TRUE;
  
  lsh_list_init(s->known_hashes);  

  s->first_file_processed = TRUE;
  s->mode                 = mode_none;

  s->threshold = 0;

  return FALSE;
}


static void usage(void)
{
  printf ("%s version %s by Jesse Kornblum%s", __progname, VERSION, NEWLINE);
  printf ("Copyright (C) 2006 ManTech International Corporation%s", NEWLINE);
  printf ("Usage: %s [-V|h] [-m file] [-vprdsblc] [-t val] [FILES]%s%s", 
	  __progname, NEWLINE, NEWLINE);

  printf ("-v - Verbose mode.%s", NEWLINE);
  printf ("-p - Pretty matching mode. Similar to -d but includes all matches%s", NEWLINE);
  printf ("-r - Recursive mode%s", NEWLINE);
  printf ("-d - Directory mode, compare all files in a directory%s", NEWLINE);
  printf ("-s - Silent mode; all errors are supressed%s", NEWLINE);
  printf ("-b - Uses only the bare name of files; all path information omitted%s", NEWLINE);
  printf ("-l - Uses relative paths for filenames%s", NEWLINE);
  printf ("-c - Prints output in CSV format%s", NEWLINE);
  printf ("-t - Only displays matches above the given threshold%s", NEWLINE);
  printf ("-m - Match FILES against known hashes in file%s", NEWLINE);
  printf ("-h - Display this help message%s", NEWLINE);
  printf ("-V - Display version number and exit%s", NEWLINE);
}






static void process_cmd_line(state *s, int argc, char **argv)
{
  int i, match_files_loaded = FALSE;
  while ((i=getopt(argc,argv,"vhVpdsblct:rm:")) != -1) {
    switch(i) {

    case 'v': 
      if (MODE(mode_verbose))
      {
	print_error(s,NULL,"Already at maximum verbosity");
	print_error(s,NULL,"Error message display to user correctly");
      }
      else
	s->mode |= mode_verbose;
      break;
      
    case 'p':
      s->mode |= mode_match_pretty;
      break;

    case 'd':
      s->mode |= mode_directory; 
      break;

    case 's':
      s->mode |= mode_silent; break;

    case 'b':
      s->mode |= mode_barename; break;

    case 'l':
      s->mode |= mode_relative; break;

    case 'c':
      s->mode |= mode_csv; break;

    case 'r':
      s->mode |= mode_recursive; break;

    case 't':
      s->threshold = (uint8_t)atol(optarg);
      if (s->threshold > 100)
	fatal_error("%s: Illegal threshold", __progname);
      s->mode |= mode_threshold;
      break;
      
    case 'm':
      s->mode |= mode_match;
      if (!match_load(s,optarg))
	match_files_loaded = TRUE;
      break;
      
    case 'h':
      usage(); 
      exit (EXIT_SUCCESS);
      
    case 'V':
      printf ("%s%s", VERSION, NEWLINE);
      exit (EXIT_SUCCESS);
      
    default:
      try();
    }
  }

  sanity_check(s,
	       ((s->mode & mode_match) && !match_files_loaded),
	       "No matching files loaded");
  
  sanity_check(s,
	       ((s->mode & mode_barename) && (s->mode & mode_relative)),
	       "Relative paths and bare names are mutually exclusive");

  sanity_check(s,
	       ((s->mode & mode_match_pretty) && (s->mode & mode_directory)),
	       "Directory mode and pretty matching are mutallty exclusive");
}





#ifdef _WIN32
static int prepare_windows_command_line(state *s)
{
  int argc;
  TCHAR **argv;

  argv = CommandLineToArgvW(GetCommandLineW(),&argc);
  
  s->argc = argc;
  s->argv = argv;

  return FALSE;
}
#endif



static int is_absolute_path(TCHAR *fn)
{
  if (NULL == fn)
    internal_error("Unknown error in is_absolute_path");
  
#ifdef _WIN32
  return FALSE;
#endif

  return (DIR_SEPARATOR == fn[0]);
}



void generate_filename(state *s, TCHAR *fn, TCHAR *cwd, TCHAR *input)
{
  if (NULL == fn || NULL == input)
    internal_error("Error calling generate_filename");

  if ((s->mode & mode_relative) || is_absolute_path(input))
    _tcsncpy(fn,input,PATH_MAX);
  else
    {
      /* Windows systems don't have symbolic links, so we don't
       have to worry about carefully preserving the paths
       they follow. Just use the system command to resolve the paths */   
#ifdef _WIN32
      _wfullpath(fn,input,PATH_MAX);
#else     
      if (NULL == cwd)
	/* If we can't get the current working directory, we're not
         going to be able to build the relative path to this file anyway.
         So we just call realpath and make the best of things */
	realpath(input,fn);
      else
	snprintf(fn,PATH_MAX,"%s%c%s",cwd,DIR_SEPARATOR,input);
#endif
    }
}






int main(int argc, char **argv)
{
  int count, status;
  state *s;
  TCHAR *fn, *cwd;

#ifndef __GLIBC__
  __progname  = basename(argv[0]);
#endif

  s = (state *)malloc(sizeof(state));
  // We can't use fatal_error because it requires a valid state
  if (NULL == s)
    fatal_error("%s: Unable to allocate state variable", __progname);

  if (initialize_state(s))
    fatal_error("%s: Unable to initialize state variable", __progname);

  process_cmd_line(s,argc,argv);

#ifdef _WIN32
  if (prepare_windows_command_line(s))
    fatal_error("%s: Unable to process command line arguments", __progname);
#else
  s->argc = argc;
  s->argv = argv;
#endif

  /* Anything left on the command line at this point is a file
     or directory we're supposed to process. If there's nothing
     specified, we should tackle standard input */
  if (optind == argc)
    fatal_error("%s: No input files", __progname);
  else
    {
      MD5DEEP_ALLOC(TCHAR,fn,PATH_MAX);
      MD5DEEP_ALLOC(TCHAR,cwd,PATH_MAX);

      cwd = _tgetcwd(cwd,PATH_MAX);
      if (NULL == cwd)
	fatal_error("%s: %s", __progname, strerror(errno));

      count = optind;

      while (count < s->argc)
	{  
	  generate_filename(s,fn,cwd,s->argv[count]);

#ifdef _WIN32
	  status = process_win32(s,fn);
#else
	  status = process_normal(s,fn);
#endif

	  ++count;
	}

      free(fn);
      free(cwd);
    }



  return (EXIT_SUCCESS);
}
