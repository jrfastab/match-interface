/*******************************************************************************
  Copyright (c) <2015>, Intel Corporation

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Intel Corporation nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#ifndef _MATCH_VERSION_H
#define _MATCH_VERSION_H

#include <string.h>

/* All version macros need to be kept in sync with the
 * AC_INIT macro in configure.ac.
 *
 * Note: there should be no hyphens in the version number
 * to be compatible with rpmbuild.
 *
 * The following conventions should be followed for versioning.
 *
 * 0.0.0dev    Development on 0.0.0
 * 0.0.1rc1    Release Candidate 1
 * 0.0.1rc2    Release Candidate 2
 * ...
 * 0.0.1       Release 0.0.1
 * 0.0.1dev    Development on 0.0.1
 */
#define MATCH_VER_MAJOR  0
#define MATCH_VER_MINOR  0
#define MATCH_VER_LEVEL  0

/*
 * EXTRA can be
 *   16     - for development versions
 *   15     - for released versions
 *   1..14  - for release candidates
 *
 * It is used along with the Major, Minor, and Level version numbers to
 * formulate a complete version number. The version number will be higher
 * for more recent versions.
 */
#define MATCH_VER_EXTRA  16

/*
 * SUFFIX can be
 *   "dev" - for development versions
 *   ""     - for released versions
 *   "rc"  - for release candidates
 */
#define MATCH_VER_SUFFIX "dev"

#define MATCH_VER_NUM(a,b,c,d) ((a) << 24 | (b) << 16 | (c) << 8 | (d))

/* Use this to compare release candiates and release versions */
#define MATCH_VERSION MATCH_VER_NUM(MATCH_VER_MAJOR, MATCH_VER_MINOR,\
                                    MATCH_VER_LEVEL, MATCH_VER_EXTRA)

#define MATCH_VERSION_STRING_LEN 32

static inline const char *match_version(void)
{
	static char s[MATCH_VERSION_STRING_LEN];

	if (s[0] != 0)
		return s;

	if (strlen(MATCH_VER_SUFFIX) == 0)
		snprintf(s, sizeof(s), "%d.%d.%d",
		         MATCH_VER_MAJOR,
		         MATCH_VER_MINOR,
		         MATCH_VER_LEVEL);
	else if (!strcmp(MATCH_VER_SUFFIX, "-dev"))
		snprintf(s, sizeof(s), "%d.%d.%d%s",
		         MATCH_VER_MAJOR,
		         MATCH_VER_MINOR,
		         MATCH_VER_LEVEL,
		         MATCH_VER_SUFFIX);
	else
		snprintf(s, sizeof(s), "%d.%d.%d%s%d",
		         MATCH_VER_MAJOR,
		         MATCH_VER_MINOR,
		         MATCH_VER_LEVEL,
		         MATCH_VER_SUFFIX,
		         MATCH_VER_EXTRA);

	return s;
}

#endif /* !_MATCH_VERSION_H */
