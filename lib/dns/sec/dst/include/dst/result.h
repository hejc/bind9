#ifndef DST_RESULT_H
#define DST_RESULT_H 1

#include <isc/lang.h>
#include <isc/result.h>
#include <isc/resultclass.h>

ISC_LANG_BEGINDECLS

#define DST_R_UNSUPPORTEDALG		(ISC_RESULTCLASS_DST + 0)
#define DST_R_UNSUPPORTEDTYPE		(ISC_RESULTCLASS_DST + 1)
#define DST_R_UNSUPPORTEDMODE		(ISC_RESULTCLASS_DST + 2)
#define DST_R_NULLKEY			(ISC_RESULTCLASS_DST + 3)
#define DST_R_INVALIDPUBLICKEY		(ISC_RESULTCLASS_DST + 4)
#define DST_R_INVALIDPRIVATEKEY		(ISC_RESULTCLASS_DST + 5)
#define DST_R_NAMETOOLONG		(ISC_RESULTCLASS_DST + 6)
#define DST_R_WRITEERROR		(ISC_RESULTCLASS_DST + 7)
#define DST_R_INVALIDPARAM		(ISC_RESULTCLASS_DST + 8)
#define DST_R_SIGNINITFAILURE		(ISC_RESULTCLASS_DST + 9)
#define DST_R_SIGNUPDATEFAILURE		(ISC_RESULTCLASS_DST + 10)
#define DST_R_SIGNFINALFAILURE		(ISC_RESULTCLASS_DST + 11)
#define DST_R_VERIFYINITFAILURE		(ISC_RESULTCLASS_DST + 12)
#define DST_R_VERIFYUPDATEFAILURE	(ISC_RESULTCLASS_DST + 13)
#define DST_R_VERIFYFINALFAILURE	(ISC_RESULTCLASS_DST + 14)
#define DST_R_NOTPUBLICKEY		(ISC_RESULTCLASS_DST + 15)
#define DST_R_NOTPRIVATEKEY		(ISC_RESULTCLASS_DST + 16)
#define DST_R_KEYCANNOTCOMPUTESECRET	(ISC_RESULTCLASS_DST + 17)
#define DST_R_COMPUTESECRETFAILURE	(ISC_RESULTCLASS_DST + 18)

#define DST_R_NRESULTS			19	/* Number of results */


char *                                  dst_result_totext(isc_result_t);
void					dst_result_register(void);

ISC_LANG_ENDDECLS

#endif /* DST_RESULT_H */
