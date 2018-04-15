/* Helper file for declaring TCG helper functions.
   This one expands prototypes for the helper functions.  */

#ifndef HELPER_PROTO_H
#define HELPER_PROTO_H

#include "exec/helper-head.h"

#define GEN_STUB_HELPER(name) \
    extern const char * glue(stub_, glue(helper_, name));

#define DEF_HELPER_FLAGS_0(name, flags, ret) \
GEN_STUB_HELPER(name) \
dh_ctype(ret) HELPER(name) (void);

#define DEF_HELPER_FLAGS_1(name, flags, ret, t1) \
GEN_STUB_HELPER(name) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1));

#define DEF_HELPER_FLAGS_2(name, flags, ret, t1, t2) \
GEN_STUB_HELPER(name) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1), dh_ctype(t2));

#define DEF_HELPER_FLAGS_3(name, flags, ret, t1, t2, t3) \
GEN_STUB_HELPER(name) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1), dh_ctype(t2), dh_ctype(t3));

#define DEF_HELPER_FLAGS_4(name, flags, ret, t1, t2, t3, t4) \
GEN_STUB_HELPER(name) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1), dh_ctype(t2), dh_ctype(t3), \
                                   dh_ctype(t4));

#define DEF_HELPER_FLAGS_5(name, flags, ret, t1, t2, t3, t4, t5) \
GEN_STUB_HELPER(name) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1), dh_ctype(t2), dh_ctype(t3), \
                            dh_ctype(t4), dh_ctype(t5));

#include "helper.h"
#include "trace/generated-helpers.h"
#include "tcg-runtime.h"

#undef DEF_HELPER_FLAGS_0
#undef DEF_HELPER_FLAGS_1
#undef DEF_HELPER_FLAGS_2
#undef DEF_HELPER_FLAGS_3
#undef DEF_HELPER_FLAGS_4
#undef DEF_HELPER_FLAGS_5

#undef GEN_STUB_HELPER

#endif /* HELPER_PROTO_H */
