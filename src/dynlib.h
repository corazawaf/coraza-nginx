/*
 * Cross-platform dynamic library loading abstraction.
 *
 * Wraps dlopen/dlsym/dlclose/dlerror (Unix) and
 * LoadLibrary/GetProcAddress/FreeLibrary/FormatMessage (Windows)
 * behind a common API.
 *
 * Shared between coraza-apache and coraza-nginx.
 */

#ifndef DYNLIB_H
#define DYNLIB_H

#if defined(_WIN32) || defined(_WIN64)

#include <windows.h>

typedef HMODULE dynlib_t;

/* Windows typically doesn't use "lib" prefix */
#define CORAZA_DYNLIB_BASENAME "coraza"
/* Library file extension per platform */
#define DYNLIB_EXT ".dll"

static inline dynlib_t dynlib_open(const char *path)
{
    return LoadLibraryA(path);
}

static inline void *dynlib_sym(dynlib_t lib, const char *name)
{
    return (void *)GetProcAddress(lib, name);
}

static inline int dynlib_close(dynlib_t lib)
{
    return FreeLibrary(lib) ? 0 : -1;
}

static inline const char *dynlib_error(void)
{
    static __declspec(thread) char buf[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                   0, buf, sizeof(buf), NULL);
    return buf;
}

#else /* Unix (Linux, macOS, FreeBSD, ...) */

#include <dlfcn.h>

typedef void *dynlib_t;

#define CORAZA_DYNLIB_BASENAME "libcoraza"

#ifdef __APPLE__
#define DYNLIB_EXT ".dylib"
#else
#define DYNLIB_EXT ".so"
#endif

static inline dynlib_t dynlib_open(const char *path)
{
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
}

static inline void *dynlib_sym(dynlib_t lib, const char *name)
{
    return dlsym(lib, name);
}

static inline int dynlib_close(dynlib_t lib)
{
    return dlclose(lib);
}

static inline const char *dynlib_error(void)
{
    return dlerror();
}

#endif /* _WIN32 || _WIN64 */

#endif /* DYNLIB_H */
