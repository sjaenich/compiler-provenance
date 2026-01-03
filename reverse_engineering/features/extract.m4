dnl --- Save the original AC_ARG_ENABLE ---
m4_define([_ORIG_AC_ARG_ENABLE], m4_defn([AC_ARG_ENABLE]))


m4_define([_ORIG_AC_DEFINE], m4_defn([AC_DEFINE]))

    m4_define([AC_DEFINE],[
        m4_append([_MY_DEFS], [$1=$2;])
    ])

dnl --- Override AC_ARG_ENABLE ---
m4_define([AC_ARG_ENABLE], [
  m4_define([_MY_DEFS], [])   dnl reset collector
  m4_define([_MY_STRINGS], [])
  _ORIG_AC_ARG_ENABLE([$1], [$2], [$3], [$4])
  dnl --- Append JSON entry for this option ---
  m4_append([_ENABLE_JSON_ENTRIES],
[ name: $1
  help: ]]m4_expand([m4_normalize($2)])[[)
  definition: "]m4_defn([_MY_DEFS])[")
  logic: $3 
])
  m4_define([_MY_DEFS], [])   dnl reset for next option
])

