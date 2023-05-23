#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([STSAFE-A_OpenSSL_Engine], [2.0.5], [benjamin.baratte@st.com])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Wno-portability])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_MACRO_DIR([m4])
# Checks for programs.
AC_PROG_CC
LT_INIT()
AC_PROG_MKDIR_P
AC_PROG_LN_S

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lStsafe':
#AC_CHECK_LIB([Stsafe], [main])
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([ssl], [main])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h stdint.h stdlib.h string.h strings.h sys/ioctl.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_gettime memmove memset socket strcasecmp strerror])

AC_CONFIG_FILES([Makefile])

PKG_PROG_PKG_CONFIG([0.25])
PKG_CHECK_MODULES([CRYPTO], [libcrypto >= 1.1.1],
                  [ac_enginesdir=`$PKG_CONFIG --variable=enginesdir libcrypto`])


AC_ARG_WITH([enginesdir], 
            [AS_HELP_STRING([--with-enginesdir],
                            [Set the OpenSSL engine directory (default: use pkg-config)])],
            [],
            [with_enginesdir=$ac_enginesdir])
AS_IF([test -z "$with_enginesdir"],
    [AC_MSG_WARN([Empty enginesdir, using $libdir/engines instead.])])
# This weirdness is necessary to enable distcheck via DISTCHECK_CONFIGURE_FLAGS
AS_IF([test -z "$with_enginesdir"],
    [with_enginesdir=$libdir/engines])
AC_SUBST(ENGINESDIR, "$with_enginesdir")

AC_ARG_WITH([debug],
            [  --with-debug[=level]    Turn on debugging],
            [debug_level=$withval
             has_debug=true],
            [has_debug=false
             debug_level=0
            ])
AM_CONDITIONAL([DEBUG], [test x$has_debug = xtrue])
AC_SUBST(DEBUG_LEVEL, $debug_level)

AC_ARG_ENABLE([stsafe_a100],
[  --enable-stsafe_a100 use STSAFE-A100 instead of STSAFE-A110],
[case "${enableval}" in
  yes) a100=true ;;
  no)  a100=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-stsafe_a100]) ;;
esac],[a100=false])
AM_CONDITIONAL([STSAFE_A100], [test x$stsafe_a100 = xtrue])

AC_ARG_ENABLE([ecdsa_verify],
[  --disable-ecdsa_verify disable ECDSA verify with STSAFE-A],
[case "${enableval}" in
  yes) ecdsa_verify=true ;;
  no)  ecdsa_verify=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --disable-ecdsa_verify]) ;;
esac],[ecdsa_verify=true])
AM_CONDITIONAL([STSAFE_NO_ECDSA_VERIFY], [test x$ecdsa_verify = xfalse])

AC_ARG_ENABLE([ecdh],
[  --disable-ecdh disable ECDH with STSAFE-A],
[case "${enableval}" in
  yes) ecdh_enable=true ;;
  no)  ecdh_enable=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --disable-ecdh]) ;;
esac],[ecdh_enable=true])
AM_CONDITIONAL([STSAFE_NO_ECDH], [test x$ecdh_enable = xfalse])


AC_ARG_WITH([i2c-addr],
            [ --with-i2c-addr= select I2C address],
            [ i2c_addr=$withval ],
            )

AM_CONDITIONAL([HAS_I2C_ADDR], test x$i2c_addr != x)
AC_SUBST([I2C_ADDR], [$i2c_addr])

AC_ARG_WITH([i2c-bus],
            [ --with-i2c-bus= select I2C bus index],
            [ i2c_bus=$withval ],
            )

AM_CONDITIONAL([HAS_I2C_BUS], test x$i2c_bus != x)
AC_SUBST([I2C_BUS], [$i2c_bus])

AC_OUTPUT

AC_MSG_RESULT([
$PACKAGE_NAME $VERSION
    enginesdir     : $with_enginesdir
    debug          : $debug_level
    i2c_addr       : $i2c_addr
    i2c_bus        : $i2c_bus
    ecdsa_verify   : $ecdsa_verify
    ecdh           : $ecdh_enable
])
