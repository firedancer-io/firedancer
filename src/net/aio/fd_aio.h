#ifndef HEADER_fd_aio_h
#define HEADER_fd_aio_h

#include <string.h>

/* defines an abstraction for input/output

   Example Usage : connecting xdp to quic

     fd_quic_t * quic = get_quic(); // get an initialized quic instance
     fd_xdp_t *  xdp  = get_xdp();  // get an initialized xdp instance

     fd_aio_t aio_xdp_to_quic;
     fd_aio_t aio_quic_to_xdp;

     fd_quic_set_aio( quic, aio_xdp_to_quic, aio_quic_to_xdp );
     fd_xdp_set_aio( xdp, aio_quic_to_xdp, aio_xdp_to_quic );

     // the two *set_aio calls have the following effect:
     //   aio_xdp_to_quic.cb_receive = fd_aio_cb_receive;
     //   aio_xdp_to_quic.context    = quic;

     //   aio_quic_to_xdp.cb_receive = fd_xdp_aio_cb_receive;
     //   aio_quic_to_xdp.context    = xdp;

     // now whenever fd_quic_process is called on quic, quic will
     // be able to send data to xdp via fd_aio_send(...)
     // and vice versa


   Direct example
     fd_aio_t aio;

     aio.cb_receive = my_cb_receive;
     aio.context    = quic;

     fd_aio_buffer_t batch[10] = {{ .data = data, .data_sz = data_sz }};

     fd_aio_buffer_t cur_batch    = batch;
     size_t          cur_batch_sz = 10;
     while( cur_batch_sz ) {
       int send_rc = fd_aio_send( aio, cur_batch, cur_batch_sz ); // send a batch of buffers to the peer
       if( send_rc < 0 ) {
         fprintf( stderr, "error occurred during send\n" );
         break;
       }
       cur_batch    += send_rc;
       cur_batch_sz -= send_rc;

       // possibly do some other process that might free up resources
       // to avoid deadlock
     }


*/

/* forward declares */
typedef struct fd_aio        fd_aio_t;
typedef struct fd_aio_buffer fd_aio_buffer_t;

/* function prototypes */

/* fd_aio_cb_receive passes data to receiver

   args
     context    contains the user context
     batch      contains pointer to an array of fd_aio_buffer_t objects
                  each containing a pointer to a buffer and the size of the buffer
     batch_sz   contains the size of the batch

   returns
     the number of buffers processed, including zero
     or ~0 if an error occurred */
typedef size_t (*fd_aio_cb_receive)( void *            context,
                                     fd_aio_buffer_t * batch,
                                     size_t            batch_sz );

struct fd_aio_buffer {
  void * data;
  size_t data_sz;
};

struct fd_aio {
  fd_aio_cb_receive cb_receive; // cb_receive called to receive data
  void *            context;
};


/* send a batch of buffers thru the aio

   args
     aio       the aio to send via
     batch     the array of fd_aio_buffer_t objects
     batch_sz  the size of the array

   returns
     N == 0       no buffers were processed, you may try again
     N >  0       N buffers were processed
     N == ~0      a fatal error occurred */
inline
size_t
fd_aio_send( fd_aio_t *        aio, 
             fd_aio_buffer_t * batch,
             size_t            batch_sz ) {
  return aio->cb_receive( aio->context, batch, batch_sz );
}

#endif

