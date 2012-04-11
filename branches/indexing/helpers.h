#ifndef __HELPERS_H
#define __HELPERS_H

// $Id$

/// Returns the string after the nth comma in the string str. If that
/// string is quoted, the quotes are removed. If there is no valid 
/// string to be found, returns true. Otherwise, returns false 
int find_comma_separated_string(char *str, unsigned int n);

/// Remove the newlines, if any. Works on both DOS and *nix newlines
void chop_line(char *s);

#endif   // ifndef __HELPERS_H
