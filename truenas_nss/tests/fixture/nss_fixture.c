// SPDX-FileCopyrightText: 2026 iXsystems, Inc, DBA TrueNAS
// SPDX-License-Identifier: MIT
/*
 * A deterministic NSS service module for this crate's test suites, built at
 * test time:
 *
 *   cc -shared -fPIC -o <out> nss_fixture.c -DNSS_FIXTURE_NAME=<infix>
 *
 * The symbols exported are _nss_<infix>_<op>, plus counters the tests read
 * back through their own dlopen of the same path. Options:
 *
 *   -DNSS_FIXTURE_THREAD_STATE=1   enumeration cursors in __thread storage
 *                                  (sss/winbind-like); default is process
 *                                  storage (files-like)
 *   -DNSS_FIXTURE_NO_GROUPS        omit the four group symbols
 *   -DNSS_FIXTURE_UNRESOLVED       reference an undefined symbol, so an
 *                                  RTLD_NOW dlopen of the fixture fails
 *   -DNSS_FIXTURE_DEFAULT_MODE="x" the mode when the environment sets none
 *   -DNSS_FIXTURE_STALE_ERANGE=n   the first n lookup calls return NOTFOUND
 *                                  with *errnop set to ERANGE
 *   -DNSS_FIXTURE_ENT_BARE_TRYAGAIN=n  the nth get*ent_r call returns
 *                                  TRYAGAIN and leaves *errnop alone,
 *                                  reporting through the thread's errno
 *   -DNSS_FIXTURE_ENT_FAULT_AT=n   the nth get*ent_r call, and every one
 *                                  after it, faults with UNAVAIL and EIO
 *                                  through the errno out-parameter without
 *                                  moving the cursor
 *   -DNSS_FIXTURE_INITGROUPS_FLOOD=n     initgroups_dyn for user
 *                                  "grouprich" appends n synthetic gids
 *                                  counting from
 *                                  NSS_FIXTURE_INITGROUPS_FLOOD_BASE
 *                                  (default 5000), forcing the array to
 *                                  grow
 *   -DNSS_FIXTURE_INITGROUPS_ERRNO=e     initgroups_dyn appends one gid,
 *                                  then returns NOTFOUND with *errnop set
 *                                  to e — the shape the real winbind
 *                                  module fails in
 *
 * The mode — "ok", "unavail", "tryagain", "notfound" — applies to the four
 * lookups and to set*ent, and is read per call from
 * NSS_FIXTURE_<infix>_MODE so a parent process can steer each fixture of a
 * child independently. end*ent always succeeds, so teardown counters stay
 * meaningful in every mode.
 *
 * No -Wl,-soname is ever passed when building this file: a fixture carrying
 * DT_SONAME libnss_files.so.2 would satisfy a later in-process dlopen of
 * that soname and hijack the registry of the very crate under test.
 */

#include <errno.h>
#include <grp.h>
#include <nss.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef NSS_FIXTURE_NAME
#error "NSS_FIXTURE_NAME must be defined"
#endif

#ifndef NSS_FIXTURE_DEFAULT_MODE
#define NSS_FIXTURE_DEFAULT_MODE "ok"
#endif

#ifndef NSS_FIXTURE_INITGROUPS_FLOOD_BASE
#define NSS_FIXTURE_INITGROUPS_FLOOD_BASE 5000
#endif

#define XCAT(a, b) a##b
#define CAT(a, b) XCAT(a, b)
#define PREFIX CAT(_nss_, NSS_FIXTURE_NAME)
#define FN(op) CAT(PREFIX, CAT(_, op))

#define XSTR(s) #s
#define STR(s) XSTR(s)
#define MODE_ENV "NSS_FIXTURE_" STR(NSS_FIXTURE_NAME) "_MODE"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#ifdef NSS_FIXTURE_UNRESOLVED

/* A reference no scope can satisfy, from a function the linker must keep,
 * so resolving this object's relocations fails and dlopen refuses it. */
extern long nss_fixture_unresolved_symbol(void);

long
FN(fixture_unresolved)(void)
{
	return nss_fixture_unresolved_symbol();
}

#endif /* NSS_FIXTURE_UNRESOLVED */

/* Counters the tests read; each raw call increments, retries included. */
long FN(fixture_lookup_calls) = 0;
long FN(fixture_getent_calls) = 0;
long FN(fixture_setent_calls) = 0;
long FN(fixture_endent_calls) = 0;

#if defined(NSS_FIXTURE_THREAD_STATE) && NSS_FIXTURE_THREAD_STATE
#define ENT_STORAGE __thread
#else
#define ENT_STORAGE
#endif

static ENT_STORAGE size_t pw_cursor = 0;
#ifndef NSS_FIXTURE_NO_GROUPS
static ENT_STORAGE size_t gr_cursor = 0;
#endif

/* Written into every pw_passwd/gr_passwd: invalid UTF-8, so a consumer
 * that reads the field it must never read fails loudly. */
static const char junk_passwd[] = "\xff\xfe";

/* A cursor call that faults without moving the cursor, so every retry
 * returns the same thing. */
#ifdef NSS_FIXTURE_ENT_FAULT_AT
#define ENT_FAULT(errnop)                                                   \
	do {                                                                \
		if (FN(fixture_getent_calls) >= (NSS_FIXTURE_ENT_FAULT_AT)) {\
			*(errnop) = EIO;                                    \
			return NSS_STATUS_UNAVAIL;                          \
		}                                                           \
	} while (0)
#else
#define ENT_FAULT(errnop) do { } while (0)
#endif

typedef enum {
	MODE_OK,
	MODE_UNAVAIL,
	MODE_TRYAGAIN,
	MODE_NOTFOUND,
} fixture_mode_t;

static fixture_mode_t
mode(void)
{
	const char *m = getenv(MODE_ENV);

	if (m == NULL)
		m = NSS_FIXTURE_DEFAULT_MODE;
	if (strcmp(m, "unavail") == 0)
		return MODE_UNAVAIL;
	if (strcmp(m, "tryagain") == 0)
		return MODE_TRYAGAIN;
	if (strcmp(m, "notfound") == 0)
		return MODE_NOTFOUND;
	return MODE_OK;
}

/* The non-ok modes, as a lookup result. UNAVAIL is status-only; TRYAGAIN
 * carries EAGAIN through the errno out-parameter. */
static enum nss_status
mode_result(fixture_mode_t m, int *errnop)
{
	switch (m) {
	case MODE_UNAVAIL:
		return NSS_STATUS_UNAVAIL;
	case MODE_TRYAGAIN:
		*errnop = EAGAIN;
		return NSS_STATUS_TRYAGAIN;
	default:
		return NSS_STATUS_NOTFOUND;
	}
}

/* --- fixed tables --------------------------------------------------------
 * "gecos-giant" needs 3072 bytes of gecos plus the other strings: more
 * than 2048 and less than 4096, so a 1024-byte first buffer is doubled
 * exactly twice. "b\xff" "ad" is not UTF-8 (the split literal keeps the
 * hex escape to one byte). */

#define A64 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define A256 A64 A64 A64 A64
#define A1024 A256 A256 A256 A256
#define A3072 A1024 A1024 A1024

struct fixture_user {
	const char *name;
	uid_t uid;
	gid_t gid;
	const char *gecos; /* NULL stays NULL in the result */
	const char *dir;
	const char *shell;
};

static const struct fixture_user users[] = {
	{ "alice", 1000, 1000, "Alice Fixture", "/home/alice", "/bin/sh" },
	{ "bob", 1001, 1001, NULL, "/home/bob", "/bin/sh" },
	{ "gecos-giant", 1002, 1002, A3072, "/home/giant", "/bin/sh" },
	{ "b\xff" "ad", 1003, 1003, "not utf-8", "/", "/bin/false" },
	{ "carol", 1004, 1004, "Carol Fixture", "/home/carol", "/bin/zsh" },
	{ "dave", 1005, 1005, "g\xff" "ecos", "/home/dave", "/bin/sh" },
	/* The winbind domain separator: opaque bytes to the consumer. */
	{ "FIXDOM\\eve", 1006, 1006, "Eve Fixture", "/home/eve", "/bin/sh" },
};

#ifndef NSS_FIXTURE_NO_GROUPS

struct fixture_group {
	const char *name;
	gid_t gid;
	/* NULL-terminated member list, or NULL for a NULL gr_mem. */
	const char *const *members;
};

static const char *const alpha_members[] = { "alice", "bob", NULL };
static const char *const empty_members[] = { NULL };
static const char *const giant_members[] = { A3072, NULL };
static const char *const domadmins_members[] = {
	"alice", "FIXDOM\\eve", NULL
};

static const struct fixture_group groups[] = {
	{ "alpha", 2000, alpha_members },
	{ "empty", 2001, empty_members },
	{ "nullmem", 2002, NULL },
	{ "giant", 2003, giant_members },
	{ "domadmins", 2004, domadmins_members },
};

#endif /* !NSS_FIXTURE_NO_GROUPS */

/* --- entry filling, with the glibc ERANGE convention --------------------- */

static enum nss_status
fill_passwd(const struct fixture_user *u, struct passwd *result,
            char *buffer, size_t buflen, int *errnop)
{
	size_t need;
	char *p;

	need = strlen(u->name) + 1 + sizeof(junk_passwd) +
	    (u->gecos ? strlen(u->gecos) + 1 : 0) +
	    strlen(u->dir) + 1 + strlen(u->shell) + 1;
	if (need > buflen) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	}

	p = buffer;
	result->pw_name = p;
	p = stpcpy(p, u->name) + 1;
	result->pw_passwd = p;
	memcpy(p, junk_passwd, sizeof(junk_passwd));
	p += sizeof(junk_passwd);
	result->pw_uid = u->uid;
	result->pw_gid = u->gid;
	if (u->gecos) {
		result->pw_gecos = p;
		p = stpcpy(p, u->gecos) + 1;
	} else {
		result->pw_gecos = NULL;
	}
	result->pw_dir = p;
	p = stpcpy(p, u->dir) + 1;
	result->pw_shell = p;
	p = stpcpy(p, u->shell) + 1;
	return NSS_STATUS_SUCCESS;
}

/* A module may report a failure through the thread's errno and leave
 * *errnop alone: glibc's frontends pass &errno as that parameter, so for
 * them the two are one location. Returns 1 on the nth get*ent_r call. */
static int
bare_tryagain(void)
{
#if defined(NSS_FIXTURE_ENT_BARE_TRYAGAIN)
	return FN(fixture_getent_calls) == NSS_FIXTURE_ENT_BARE_TRYAGAIN;
#else
	return 0;
#endif
}

/* Returns 1 while a lookup should report ERANGE under a status that is not
 * TRYAGAIN, which is not a request to enlarge the buffer. */
static int
stale_erange(void)
{
#if defined(NSS_FIXTURE_STALE_ERANGE)
	return FN(fixture_lookup_calls) <= NSS_FIXTURE_STALE_ERANGE;
#else
	return 0;
#endif
}

/* --- passwd -------------------------------------------------------------- */

enum nss_status
FN(getpwnam_r)(const char *name, struct passwd *result, char *buffer,
               size_t buflen, int *errnop)
{
	fixture_mode_t m = mode();
	size_t i;

	FN(fixture_lookup_calls)++;
	if (stale_erange()) {
		*errnop = ERANGE;
		return NSS_STATUS_NOTFOUND;
	}
	if (m != MODE_OK)
		return mode_result(m, errnop);
	for (i = 0; i < ARRAY_SIZE(users); i++) {
		if (strcmp(name, users[i].name) == 0)
			return fill_passwd(&users[i], result, buffer,
			    buflen, errnop);
	}
	return NSS_STATUS_NOTFOUND;
}

enum nss_status
FN(getpwuid_r)(uid_t uid, struct passwd *result, char *buffer,
               size_t buflen, int *errnop)
{
	fixture_mode_t m = mode();
	size_t i;

	FN(fixture_lookup_calls)++;
	if (m != MODE_OK)
		return mode_result(m, errnop);
	for (i = 0; i < ARRAY_SIZE(users); i++) {
		if (users[i].uid == uid)
			return fill_passwd(&users[i], result, buffer,
			    buflen, errnop);
	}
	return NSS_STATUS_NOTFOUND;
}

enum nss_status
FN(setpwent)(int stayopen)
{
	(void)stayopen;
	FN(fixture_setent_calls)++;
	if (mode() != MODE_OK)
		return NSS_STATUS_UNAVAIL;
	pw_cursor = 0;
	return NSS_STATUS_SUCCESS;
}

enum nss_status
FN(endpwent)(void)
{
	FN(fixture_endent_calls)++;
	pw_cursor = 0;
	return NSS_STATUS_SUCCESS;
}

enum nss_status
FN(getpwent_r)(struct passwd *result, char *buffer, size_t buflen,
               int *errnop)
{
	enum nss_status s;

	FN(fixture_getent_calls)++;
	ENT_FAULT(errnop);
	if (bare_tryagain()) {
		errno = EAGAIN;
		return NSS_STATUS_TRYAGAIN;
	}
	if (pw_cursor >= ARRAY_SIZE(users))
		return NSS_STATUS_NOTFOUND;
	s = fill_passwd(&users[pw_cursor], result, buffer, buflen, errnop);
	/* An ERANGE retry re-serves the same index. */
	if (s == NSS_STATUS_SUCCESS)
		pw_cursor++;
	return s;
}

/* --- group --------------------------------------------------------------- */

#ifndef NSS_FIXTURE_NO_GROUPS

static enum nss_status
fill_group(const struct fixture_group *g, struct group *result,
           char *buffer, size_t buflen, int *errnop)
{
	size_t nmem = 0;
	size_t align = _Alignof(char *);
	size_t off = (align - ((uintptr_t)buffer % align)) % align;
	size_t vec_bytes;
	size_t need;
	char **vec = NULL;
	char *p;
	size_t i;

	if (g->members != NULL)
		while (g->members[nmem] != NULL)
			nmem++;
	vec_bytes = g->members ? (nmem + 1) * sizeof(char *) : 0;

	need = off + vec_bytes + strlen(g->name) + 1 + sizeof(junk_passwd);
	for (i = 0; i < nmem; i++)
		need += strlen(g->members[i]) + 1;
	if (need > buflen) {
		*errnop = ERANGE;
		return NSS_STATUS_TRYAGAIN;
	}

	p = buffer + off;
	if (g->members != NULL) {
		vec = (char **)p;
		p += vec_bytes;
	}
	result->gr_name = p;
	p = stpcpy(p, g->name) + 1;
	result->gr_passwd = p;
	memcpy(p, junk_passwd, sizeof(junk_passwd));
	p += sizeof(junk_passwd);
	result->gr_gid = g->gid;
	for (i = 0; i < nmem; i++) {
		vec[i] = p;
		p = stpcpy(p, g->members[i]) + 1;
	}
	if (vec != NULL)
		vec[nmem] = NULL;
	result->gr_mem = vec;
	return NSS_STATUS_SUCCESS;
}

enum nss_status
FN(getgrnam_r)(const char *name, struct group *result, char *buffer,
               size_t buflen, int *errnop)
{
	fixture_mode_t m = mode();
	size_t i;

	FN(fixture_lookup_calls)++;
	if (m != MODE_OK)
		return mode_result(m, errnop);
	for (i = 0; i < ARRAY_SIZE(groups); i++) {
		if (strcmp(name, groups[i].name) == 0)
			return fill_group(&groups[i], result, buffer,
			    buflen, errnop);
	}
	return NSS_STATUS_NOTFOUND;
}

enum nss_status
FN(getgrgid_r)(gid_t gid, struct group *result, char *buffer,
               size_t buflen, int *errnop)
{
	fixture_mode_t m = mode();
	size_t i;

	FN(fixture_lookup_calls)++;
	if (m != MODE_OK)
		return mode_result(m, errnop);
	for (i = 0; i < ARRAY_SIZE(groups); i++) {
		if (groups[i].gid == gid)
			return fill_group(&groups[i], result, buffer,
			    buflen, errnop);
	}
	return NSS_STATUS_NOTFOUND;
}

enum nss_status
FN(setgrent)(int stayopen)
{
	(void)stayopen;
	FN(fixture_setent_calls)++;
	if (mode() != MODE_OK)
		return NSS_STATUS_UNAVAIL;
	gr_cursor = 0;
	return NSS_STATUS_SUCCESS;
}

enum nss_status
FN(endgrent)(void)
{
	FN(fixture_endent_calls)++;
	gr_cursor = 0;
	return NSS_STATUS_SUCCESS;
}

enum nss_status
FN(getgrent_r)(struct group *result, char *buffer, size_t buflen,
               int *errnop)
{
	enum nss_status s;

	FN(fixture_getent_calls)++;
	ENT_FAULT(errnop);
	if (bare_tryagain()) {
		errno = EAGAIN;
		return NSS_STATUS_TRYAGAIN;
	}
	if (gr_cursor >= ARRAY_SIZE(groups))
		return NSS_STATUS_NOTFOUND;
	s = fill_group(&groups[gr_cursor], result, buffer, buflen, errnop);
	/* An ERANGE retry re-serves the same index. */
	if (s == NSS_STATUS_SUCCESS)
		gr_cursor++;
	return s;
}

/* --- initgroups ---------------------------------------------------------- */

long FN(fixture_initgroups_calls) = 0;
/* The limit the last initgroups_dyn call received, for readback. */
long FN(fixture_initgroups_limit) = 0;

/* Append one gid through the initgroups_dyn array protocol: the doubling
 * realloc the real modules use, honouring a positive limit the way
 * winbind does — stop appending, keep the status. Returns 1 when the gid
 * was appended, 0 at the limit, -1 on ENOMEM with *errnop set. */
static int
ig_append(gid_t gid, long int *start, long int *size, gid_t **groupsp,
          long int limit, int *errnop)
{
	long int newsize;
	gid_t *grown;

	if (*start == *size) {
		newsize = 2 * (*size);
		if (limit > 0) {
			if (*size >= limit)
				return 0;
			if (newsize > limit)
				newsize = limit;
		}
		grown = realloc(*groupsp, newsize * sizeof(**groupsp));
		if (grown == NULL) {
			*errnop = ENOMEM;
			return -1;
		}
		*groupsp = grown;
		*size = newsize;
	}
	(*groupsp)[*start] = gid;
	(*start)++;
	return 1;
}

enum nss_status
FN(initgroups_dyn)(const char *user, gid_t group, long int *start,
                   long int *size, gid_t **groupsp, long int limit,
                   int *errnop)
{
	fixture_mode_t m = mode();
	int appended = 0;
	size_t i, j;

	FN(fixture_initgroups_calls)++;
	FN(fixture_initgroups_limit) = limit;
	if (m != MODE_OK)
		return mode_result(m, errnop);
#ifdef NSS_FIXTURE_INITGROUPS_ERRNO
	if (ig_append(2000, start, size, groupsp, limit, errnop) < 0)
		return NSS_STATUS_NOTFOUND;
	*errnop = NSS_FIXTURE_INITGROUPS_ERRNO;
	return NSS_STATUS_NOTFOUND;
#endif
#ifdef NSS_FIXTURE_INITGROUPS_FLOOD
	if (strcmp(user, "grouprich") == 0) {
		for (j = 0; j < NSS_FIXTURE_INITGROUPS_FLOOD; j++) {
			switch (ig_append(
			    (gid_t)(NSS_FIXTURE_INITGROUPS_FLOOD_BASE + j),
			    start, size, groupsp, limit, errnop)) {
			case -1:
				return NSS_STATUS_NOTFOUND;
			case 0:
				goto out;
			}
			appended = 1;
		}
	}
#endif
	for (i = 0; i < ARRAY_SIZE(groups); i++) {
		if (groups[i].members == NULL)
			continue;
		for (j = 0; groups[i].members[j] != NULL; j++) {
			if (strcmp(groups[i].members[j], user) != 0)
				continue;
			/* Skip the primary, as winbind does. */
			if (groups[i].gid == group)
				break;
			switch (ig_append(groups[i].gid, start, size,
			    groupsp, limit, errnop)) {
			case -1:
				return NSS_STATUS_NOTFOUND;
			case 0:
				goto out;
			}
			appended = 1;
			break;
		}
	}
out:
	return appended ? NSS_STATUS_SUCCESS : NSS_STATUS_NOTFOUND;
}

#endif /* !NSS_FIXTURE_NO_GROUPS */
