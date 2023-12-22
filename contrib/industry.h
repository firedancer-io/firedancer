/* The following functions must be implemented (and exported) in order for
   industry to be able to use your target. */

/* industry_{init,fini} are optional */
int industry_init( int *    pargc,
                   char *** pargv );
int industry_exit( void );

/* industry_test_one must be implemented */
int industry_test_one( unsigned long * out_result_sz,
                       unsigned char * out_result_buf,
                       unsigned long result_buf_sz,
                       unsigned char * data,
                       unsigned long data_sz
);
