#ifndef HEADER_industry_h
#define HEADER_industry_h

/* Authoritative version at https://github.com/firedancer-io/industry/blob/main/include/industry.h */

/* The following functions must be implemented (and exported) in order for
   industry to be able to use your target. */

#define INDUSTRY_API_VERSION (1UL)

/* industry_{init,fini} are optional */
int
industry_init( int *    pargc,
               char *** pargv );

int
industry_fini( void );

/* industry_test_one must be implemented */
int
industry_test_one( unsigned long * out_result_sz,
                   unsigned char * out_result_buf,
                   unsigned long result_buf_sz,
                   unsigned char * data,
                   unsigned long data_sz
);

unsigned long
industry_api_ver( void ) {
   return INDUSTRY_API_VERSION;
}

#endif /* HEADER_industry_h */
