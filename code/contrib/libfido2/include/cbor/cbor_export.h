
#ifndef CBOR_EXPORT_H
#define CBOR_EXPORT_H

#ifdef CBOR_STATIC_DEFINE
#  define CBOR_EXPORT
#  define CBOR_NO_EXPORT
#else
#  ifndef CBOR_EXPORT
#    ifdef cbor_EXPORTS
        /* We are building this library */
#      define CBOR_EXPORT __declspec(dllexport)
#    else
        /* We are using this library */
#      define CBOR_EXPORT __declspec(dllimport)
#    endif
#  endif

#  ifndef CBOR_NO_EXPORT
#    define CBOR_NO_EXPORT 
#  endif
#endif

#ifndef CBOR_DEPRECATED
#  define CBOR_DEPRECATED __declspec(deprecated)
#endif

#ifndef CBOR_DEPRECATED_EXPORT
#  define CBOR_DEPRECATED_EXPORT CBOR_EXPORT CBOR_DEPRECATED
#endif

#ifndef CBOR_DEPRECATED_NO_EXPORT
#  define CBOR_DEPRECATED_NO_EXPORT CBOR_NO_EXPORT CBOR_DEPRECATED
#endif

#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef CBOR_NO_DEPRECATED
#    define CBOR_NO_DEPRECATED
#  endif
#endif

#endif /* CBOR_EXPORT_H */
