#include "fd_gossip_msg.h"
#include "fd_gossip_crds.h"
#include <stdlib.h>
#include <stdio.h>

/* deserialization-serialization roundtrip for gossip messages.
   this routine starts with a serialized msg blob taken off the wire and deserializes it.
   it then serializes the message struct back to on-the-wire format, and we check that the original
   and newly serialized message match byte-by-byte. if they match, then deserialization & serialization
   both work. */
int
test_deserialization_serialization_roundtrip( void * payload,
                                              ulong  payload_sz ) {
  uchar * deser_output = malloc( 1024*1024 );
  if( !deser_output ) {
    FD_LOG_WARNING(( "failed to allocate memory for deserialization" ));
    return 0;
  }

  fd_bin_parse_ctx_t ctx_deser;
  fd_bin_parse_init( &ctx_deser, payload, payload_sz, deser_output, 1024*1024 );
  fd_bin_parse_set_input_blob_size( &ctx_deser, payload_sz );
  fd_gossip_msg_t * msg = fd_gossip_parse_msg( &ctx_deser );
  if( !msg ) {
    FD_LOG_WARNING(( "original blob failed to parse" ));
    return 0;
  }

  fd_gossip_pretty_print( msg );

  void * ser_output = malloc( 1024*1024 );
  if( !ser_output ) {
    FD_LOG_WARNING(( "failed to allocate memory for serialization" ));
    return 0;
  }

  /* now serialize it back to a byte stream again */
  fd_bin_parse_ctx_t ctx_ser;
  fd_bin_parse_init( &ctx_ser, msg, msg->msg_sz, ser_output, 1024*1024 );
  fd_bin_parse_set_input_blob_size( &ctx_ser, msg->msg_sz );

  ulong data_out_sz = 0;
  void * out = fd_gossip_encode_msg( &ctx_ser, &data_out_sz );
  if( !out ) {
    FD_LOG_WARNING(( "failed to serialize msg struct" ));
    return 0;
  }

  /* assert that the original payload blob and the newly serialized one have the same size */
  if( data_out_sz!=payload_sz ) {
    FD_LOG_WARNING(( "original blob different size to newly serialized blob. orig %lu, new %lu", payload_sz, data_out_sz ));
    return 0;
  }

  /* ensure that the original serialized payload is the same as the one just produced 
     by `fd_gossip_encode_msg`. if the original payload and newly encoded payloads match,
     then both the deserializer and serializer work properly. */
  if( memcmp( out, payload, payload_sz ) ) {
    FD_LOG_WARNING(( "original blob different to newly serialized blob." ));

#if 0
    uchar *ptr = (uchar *)payload;
    for( ulong count=0; count<payload_sz; count++ ) {
      printf("0x%x ", ptr[count]&0xff);
    }
    printf("\n\n");
    ptr = (uchar *)out;
    for( ulong count=0; count<data_out_sz; count++ ) {
      printf("0x%x ", ptr[count]&0xff);
    }
    printf("\n\n");
#endif

    return 0;
  }

  return 1;
}

int test_contactinfo_deserialization_serialization_round_trip( void * payload,
                                                                           ulong  payload_sz ) {
  uchar * deser_output = malloc( 1024*1024 );
  if( !deser_output ) {
    FD_LOG_WARNING(( "unable to allocate memory for deserialization" ));
    return 0;
  }

  ulong obj_out_sz = 0;

/* test ping message */
  fd_bin_parse_ctx_t ctx_deser;
  fd_bin_parse_init( &ctx_deser, payload, payload_sz, deser_output, 10*2048 );
  fd_bin_parse_set_input_blob_size( &ctx_deser, payload_sz );
  int success = fd_gossip_parse_crds_contact_info( &ctx_deser, deser_output, 1024*1024, &obj_out_sz );
  if( !success ) {
    FD_LOG_WARNING(( "original blob failed to parse" ));
    return 0;
  }

  fd_gossip_pretty_print_crds_object( deser_output );

  void * ser_output = malloc( 1024*1024 );
  if( !ser_output ) {
    FD_LOG_WARNING(( "unable to allocate memory for serialization" ));
    return 0;
  }

  /* now serialize it back to a byte stream again */
  void * crds_obj = deser_output;
  ulong crds_obj_sz = obj_out_sz;
  fd_bin_parse_ctx_t ctx_ser;
  fd_bin_parse_init( &ctx_ser, crds_obj, crds_obj_sz, ser_output, 1024*1024 );
  fd_bin_parse_set_input_blob_size( &ctx_ser, crds_obj_sz );

  ulong data_out_sz = 0;
  int ser_success = fd_gossip_encode_crds_obj( &ctx_ser, crds_obj, crds_obj_sz, &data_out_sz );
  if( !ser_success ) {
    FD_LOG_WARNING(( "failed to serialize msg struct" ));
    return 0;
  }

  /* ensure that the original serialized payload is the same as the one just produced 
     by `fd_gossip_encode_crds_obj`. we compare the newly serialized data from offset 68. */
  if( memcmp( payload, ((uchar *)ser_output+68), payload_sz ) ) {
    FD_LOG_WARNING(( "original blob different to newly serialized blob." ));

#if 0
    uchar *ptr = (uchar *)payload;
    for( ulong count=0; count<payload_sz; count++ ) {
      printf("0x%x ", ptr[count]&0xff);
    }
    printf("\n\n");
    ptr = (uchar *)ser_output;
    for( ulong count=0; count<data_out_sz; count++ ) {
      printf("0x%x ", ptr[count]&0xff);
    }
    printf("\n\n");
#endif

    return 0;
  }

  return 1;
}

/* This test ensures that encoding of samples all housed in a contiguous tightly packed buffer using the same
   parse context works correctly, as might be done for a batch of outgoing gossip messages.
   To do this, this function takes four gossip message blobs and their sizes, deserializes them all to a parsed 
   gossip structure representation, and then copies all these structs into a single buffer with some nonsense
   data sandwiched between two structs on each side of it. We then try to serialize each sample back to
   a message blob, verifying that the nonsense sample does indeed fail to serialize and that serialization
   continue properly after that invalid sample is encountered by the encoder. */
int
test_contiguous_encoding( void * payload1,
                          ulong  payload1_sz,
                          void * payload2,
                          ulong  payload2_sz,
                          void * payload3,
                          ulong  payload3_sz,
                          void * payload4,
                          ulong  payload4_sz ) {
  uchar * deser1_output = malloc( 1024*1024 );
  uchar * deser2_output = malloc( 1024*1024 );
  uchar * deser3_output = malloc( 1024*1024 );
  uchar * deser4_output = malloc( 1024*1024 );

  if( !deser1_output || !deser2_output || !deser3_output || !deser4_output ) {
    FD_LOG_WARNING(( "unable to allocate memory for deserialization" ));
    return 0;
  }

  fd_bin_parse_ctx_t ctx_deser;
  fd_bin_parse_init( &ctx_deser, payload1, payload1_sz, deser1_output, 1024*1024 );
  fd_bin_parse_set_input_blob_size( &ctx_deser, payload1_sz );
  fd_gossip_msg_t * msg = fd_gossip_parse_msg( &ctx_deser );
  if( !msg ) {
    FD_LOG_WARNING(( "original blob failed to parse" ));
    return 0;
  }

  fd_bin_parse_init( &ctx_deser, payload2, payload2_sz, deser2_output, 1024*1024 );
  fd_bin_parse_set_input_blob_size( &ctx_deser, payload2_sz );
  fd_gossip_msg_t * msg2 = fd_gossip_parse_msg( &ctx_deser );
  if( !msg ) {
    FD_LOG_WARNING(( "original blob failed to parse" ));
    return 0;
  }

  fd_bin_parse_init( &ctx_deser, payload3, payload3_sz, deser3_output, 1024*1024 );
  fd_bin_parse_set_input_blob_size( &ctx_deser, payload3_sz );
  fd_gossip_msg_t * msg3 = fd_gossip_parse_msg( &ctx_deser );
  if( !msg ) {
    FD_LOG_WARNING(( "original blob failed to parse" ));
    return 0;
  }

  fd_bin_parse_init( &ctx_deser, payload4, payload4_sz, deser4_output, 1024*1024 );
  fd_bin_parse_set_input_blob_size( &ctx_deser, payload4_sz );
  fd_gossip_msg_t * msg4 = fd_gossip_parse_msg( &ctx_deser );
  if( !msg ) {
    FD_LOG_WARNING(( "original blob failed to parse" ));
    return 0;
  }

  uchar * gossip_payloads_buf = (uchar *)malloc( 1024*1024 );
  if( !gossip_payloads_buf ) {
    FD_LOG_WARNING(( "unable to allocate memory for serialization" ));
    return 0;
  }
  
  uchar * gossip_buf_ptr = (uchar *)gossip_payloads_buf;

  FD_TEST( gossip_payloads_buf );

  /* an obviously bad message in the input stream to test that parsing continues
     as normal after discarding a bad message and updating the parse context's state */
  char * bad_message = "\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61\x61";

  fd_memcpy( gossip_buf_ptr, msg, msg->msg_sz );
  gossip_buf_ptr += msg->msg_sz;
  fd_memcpy( gossip_buf_ptr, msg2, msg2->msg_sz );
  gossip_buf_ptr += msg2->msg_sz;
  fd_memcpy( gossip_buf_ptr, bad_message, 16);
  gossip_buf_ptr += 16;
  fd_memcpy( gossip_buf_ptr, msg3, msg3->msg_sz );
  gossip_buf_ptr += msg3->msg_sz;
  fd_memcpy( gossip_buf_ptr, msg4, msg4->msg_sz );
  gossip_buf_ptr += msg4->msg_sz;

  void * ser_output = malloc( 1024*1024 );
  if( !ser_output ) {
    FD_LOG_WARNING(( "failed to allocate memory for serialization" ));
    return 0;
  }

  fd_bin_parse_ctx_t contiguous_serialize_ctx;
  fd_bin_parse_init( &contiguous_serialize_ctx, gossip_payloads_buf, (ulong)(gossip_buf_ptr - gossip_payloads_buf), ser_output, 1024*1024 );

  /* now try serialize all samples in gossip_payloads_buf back to blobs again */
  fd_bin_parse_set_input_blob_size( &contiguous_serialize_ctx, msg->msg_sz );

  ulong data_out_sz = 0;
  void * out = fd_gossip_encode_msg( &contiguous_serialize_ctx, &data_out_sz );
  if( !out ) {
    FD_LOG_WARNING(( "failed to serialize msg struct (payload1)" ));
    return 0;
  }
  if( data_out_sz!= payload1_sz ) {
    FD_LOG_WARNING(( "payload out size was different size to original (payload1_sz)"));
    return 0;
  }
  if( memcmp( out, payload1, payload1_sz ) ) {
    FD_LOG_WARNING(( "serialized payload was different to original (payload1)" ));
    return 0;
  }

  fd_bin_parse_set_input_blob_size( &contiguous_serialize_ctx, msg2->msg_sz );
  out = fd_gossip_encode_msg( &contiguous_serialize_ctx, &data_out_sz );
  if( !out ) {
    FD_LOG_WARNING(( "failed to serialize msg struct (payload2)" ));
    return 0;
  }
  if( data_out_sz!= payload2_sz ) {
    FD_LOG_WARNING(( "payload out size was different size to original (payload2_sz)"));
    return 0;
  }
  if( memcmp( out, payload2, payload2_sz ) ) {
    FD_LOG_WARNING(( "serialized payload was different to original (payload2)" ));
    return 0;
  }

  /* attempt to serialize up the nonsense data. must fail. */
  fd_bin_parse_set_input_blob_size( &contiguous_serialize_ctx, 16 );
  out = fd_gossip_encode_msg( &contiguous_serialize_ctx, &data_out_sz );
  if( out ) {
    FD_LOG_WARNING(( "error - successfully serialized bad data. this should fail." ));
    return 0;
  }

  fd_bin_parse_set_input_blob_size( &contiguous_serialize_ctx, msg3->msg_sz );
  out = fd_gossip_encode_msg( &contiguous_serialize_ctx, &data_out_sz );
  if( !out ) {
    FD_LOG_WARNING(( "failed to serialize msg struct (payload3)" ));
    return 0;
  }
  if( data_out_sz!= payload3_sz ) {
    FD_LOG_WARNING(( "payload out size was different size to original (payload3_sz)"));
    return 0;
  }
  if( memcmp( out, payload3, payload3_sz ) ) {
    FD_LOG_WARNING(( "serialized payload was different to original (payload3)" ));
    return 0;
  }

  fd_bin_parse_set_input_blob_size( &contiguous_serialize_ctx, msg4->msg_sz );
  out = fd_gossip_encode_msg( &contiguous_serialize_ctx, &data_out_sz );
  if( !out ) {
    FD_LOG_WARNING(( "failed to serialize msg struct (payload4)" ));
    return 0;
  }
  if( data_out_sz!= payload4_sz ) {
    FD_LOG_WARNING(( "payload out size was different size to original (payload4_sz)"));
    return 0;
  }
  if( memcmp( out, payload4, payload4_sz ) ) {
    FD_LOG_WARNING(( "serialized payload was different to original (payload4)" ));
    return 0;
  }

  return 1;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_IMPORT_BINARY( pull_request, "src/ballet/gossip/fixtures/pull_request.bin" );
  FD_IMPORT_BINARY( pull_response_contact_info, "src/ballet/gossip/fixtures/pull_response_contact_info.bin" );
  FD_IMPORT_BINARY( ping_message, "src/ballet/gossip/fixtures/ping_message.bin" );
  FD_IMPORT_BINARY( pong_message, "src/ballet/gossip/fixtures/pong_message.bin" );
  FD_IMPORT_BINARY( pull_response_node_instance, "src/ballet/gossip/fixtures/pull_response_node_instance.bin" );
  FD_IMPORT_BINARY( push_vote_message, "src/ballet/gossip/fixtures/push_vote_message.bin" );
  FD_IMPORT_BINARY( pull_response_snapshot_hashes, "src/ballet/gossip/fixtures/pull_response_snapshot_hashes.bin" );
  FD_IMPORT_BINARY( pull_response_version, "src/ballet/gossip/fixtures/pull_response_version.bin" );
  FD_IMPORT_BINARY( prune_msg_testcase, "src/ballet/gossip/fixtures/prune_msg_testcase.bin" );
  FD_IMPORT_BINARY( gossip_msg_0, "src/ballet/gossip/fixtures/gossip_msg_0.bin" );
  FD_IMPORT_BINARY( gossip_msg_1, "src/ballet/gossip/fixtures/gossip_msg_1.bin" );
  FD_IMPORT_BINARY( gossip_msg_2, "src/ballet/gossip/fixtures/gossip_msg_2.bin" );
  FD_IMPORT_BINARY( gossip_msg_3, "src/ballet/gossip/fixtures/gossip_msg_3.bin" );
  FD_IMPORT_BINARY( gossip_msg_4, "src/ballet/gossip/fixtures/gossip_msg_4.bin" );
  FD_IMPORT_BINARY( gossip_msg_5, "src/ballet/gossip/fixtures/gossip_msg_5.bin" );
  FD_IMPORT_BINARY( gossip_msg_6, "src/ballet/gossip/fixtures/gossip_msg_6.bin" );
  FD_IMPORT_BINARY( gossip_msg_7, "src/ballet/gossip/fixtures/gossip_msg_7.bin" );
  FD_IMPORT_BINARY( gossip_msg_8, "src/ballet/gossip/fixtures/gossip_msg_8.bin" );
  FD_IMPORT_BINARY( gossip_msg_9, "src/ballet/gossip/fixtures/gossip_msg_9.bin" );
  FD_IMPORT_BINARY( gossip_msg_10, "src/ballet/gossip/fixtures/gossip_msg_10.bin" );
  FD_IMPORT_BINARY( gossip_msg_11, "src/ballet/gossip/fixtures/gossip_msg_11.bin" );
  FD_IMPORT_BINARY( gossip_msg_12, "src/ballet/gossip/fixtures/gossip_msg_12.bin" );
  FD_IMPORT_BINARY( gossip_msg_13, "src/ballet/gossip/fixtures/gossip_msg_13.bin" );
  FD_IMPORT_BINARY( gossip_msg_14, "src/ballet/gossip/fixtures/gossip_msg_14.bin" );
  FD_IMPORT_BINARY( gossip_msg_15, "src/ballet/gossip/fixtures/gossip_msg_15.bin" );
  FD_IMPORT_BINARY( gossip_msg_16, "src/ballet/gossip/fixtures/gossip_msg_16.bin" );
  FD_IMPORT_BINARY( gossip_msg_17, "src/ballet/gossip/fixtures/gossip_msg_17.bin" );
  FD_IMPORT_BINARY( gossip_msg_18, "src/ballet/gossip/fixtures/gossip_msg_18.bin" );
  FD_IMPORT_BINARY( gossip_msg_19, "src/ballet/gossip/fixtures/gossip_msg_19.bin" );
  FD_IMPORT_BINARY( gossip_msg_20, "src/ballet/gossip/fixtures/gossip_msg_20.bin" );
  FD_IMPORT_BINARY( gossip_msg_21, "src/ballet/gossip/fixtures/gossip_msg_21.bin" );
  FD_IMPORT_BINARY( gossip_msg_22, "src/ballet/gossip/fixtures/gossip_msg_22.bin" );
  FD_IMPORT_BINARY( gossip_msg_23, "src/ballet/gossip/fixtures/gossip_msg_23.bin" );
  FD_IMPORT_BINARY( gossip_msg_24, "src/ballet/gossip/fixtures/gossip_msg_24.bin" );
  FD_IMPORT_BINARY( gossip_msg_25, "src/ballet/gossip/fixtures/gossip_msg_25.bin" );
  FD_IMPORT_BINARY( gossip_msg_26, "src/ballet/gossip/fixtures/gossip_msg_26.bin" );
  FD_IMPORT_BINARY( gossip_msg_27, "src/ballet/gossip/fixtures/gossip_msg_27.bin" );
  FD_IMPORT_BINARY( gossip_msg_28, "src/ballet/gossip/fixtures/gossip_msg_28.bin" );
  FD_IMPORT_BINARY( gossip_msg_29, "src/ballet/gossip/fixtures/gossip_msg_29.bin" );
  FD_IMPORT_BINARY( gossip_msg_30, "src/ballet/gossip/fixtures/gossip_msg_30.bin" );
  FD_IMPORT_BINARY( gossip_msg_31, "src/ballet/gossip/fixtures/gossip_msg_31.bin" );
  FD_IMPORT_BINARY( gossip_msg_32, "src/ballet/gossip/fixtures/gossip_msg_32.bin" );
  FD_IMPORT_BINARY( gossip_msg_33, "src/ballet/gossip/fixtures/gossip_msg_33.bin" );
  FD_IMPORT_BINARY( gossip_msg_34, "src/ballet/gossip/fixtures/gossip_msg_34.bin" );
  FD_IMPORT_BINARY( gossip_msg_35, "src/ballet/gossip/fixtures/gossip_msg_35.bin" );
  FD_IMPORT_BINARY( gossip_msg_36, "src/ballet/gossip/fixtures/gossip_msg_36.bin" );
  FD_IMPORT_BINARY( gossip_msg_37, "src/ballet/gossip/fixtures/gossip_msg_37.bin" );
  FD_IMPORT_BINARY( gossip_msg_38, "src/ballet/gossip/fixtures/gossip_msg_38.bin" );
  FD_IMPORT_BINARY( gossip_msg_39, "src/ballet/gossip/fixtures/gossip_msg_39.bin" );
  FD_IMPORT_BINARY( gossip_msg_40, "src/ballet/gossip/fixtures/gossip_msg_40.bin" );
  FD_IMPORT_BINARY( gossip_msg_41, "src/ballet/gossip/fixtures/gossip_msg_41.bin" );
  FD_IMPORT_BINARY( gossip_msg_42, "src/ballet/gossip/fixtures/gossip_msg_42.bin" );
  FD_IMPORT_BINARY( gossip_msg_43, "src/ballet/gossip/fixtures/gossip_msg_43.bin" );
  FD_IMPORT_BINARY( gossip_msg_44, "src/ballet/gossip/fixtures/gossip_msg_44.bin" );
  FD_IMPORT_BINARY( gossip_msg_45, "src/ballet/gossip/fixtures/gossip_msg_45.bin" );
  FD_IMPORT_BINARY( gossip_msg_46, "src/ballet/gossip/fixtures/gossip_msg_46.bin" );
  FD_IMPORT_BINARY( gossip_msg_47, "src/ballet/gossip/fixtures/gossip_msg_47.bin" );
  FD_IMPORT_BINARY( gossip_msg_48, "src/ballet/gossip/fixtures/gossip_msg_48.bin" );
  FD_IMPORT_BINARY( gossip_msg_49, "src/ballet/gossip/fixtures/gossip_msg_49.bin" );
  FD_IMPORT_BINARY( gossip_msg_50, "src/ballet/gossip/fixtures/gossip_msg_50.bin" );
  FD_IMPORT_BINARY( gossip_msg_51, "src/ballet/gossip/fixtures/gossip_msg_51.bin" );
  FD_IMPORT_BINARY( gossip_msg_52, "src/ballet/gossip/fixtures/gossip_msg_52.bin" );
  FD_IMPORT_BINARY( gossip_msg_53, "src/ballet/gossip/fixtures/gossip_msg_53.bin" );
  FD_IMPORT_BINARY( gossip_msg_54, "src/ballet/gossip/fixtures/gossip_msg_54.bin" );
  FD_IMPORT_BINARY( gossip_msg_55, "src/ballet/gossip/fixtures/gossip_msg_55.bin" );
  FD_IMPORT_BINARY( gossip_msg_56, "src/ballet/gossip/fixtures/gossip_msg_56.bin" );

  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)pull_request, pull_request_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)ping_message, ping_message_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)pong_message, pong_message_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (void*)pull_response_node_instance, pull_response_node_instance_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)push_vote_message, push_vote_message_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)pull_response_snapshot_hashes, pull_response_snapshot_hashes_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)pull_response_version, pull_response_version_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)prune_msg_testcase, prune_msg_testcase_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)pull_response_contact_info, pull_response_contact_info_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_0, gossip_msg_0_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_1, gossip_msg_1_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_2, gossip_msg_2_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_3, gossip_msg_3_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_4, gossip_msg_4_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_5, gossip_msg_5_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_6, gossip_msg_6_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_7, gossip_msg_7_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_8, gossip_msg_8_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_9, gossip_msg_9_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_10, gossip_msg_10_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_11, gossip_msg_11_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_12, gossip_msg_12_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_13, gossip_msg_13_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_14, gossip_msg_14_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_15, gossip_msg_15_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_16, gossip_msg_16_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_17, gossip_msg_17_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_18, gossip_msg_18_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_19, gossip_msg_19_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_20, gossip_msg_20_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_21, gossip_msg_21_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_22, gossip_msg_22_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_23, gossip_msg_23_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_24, gossip_msg_24_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_25, gossip_msg_25_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_26, gossip_msg_26_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_27, gossip_msg_27_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_28, gossip_msg_28_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_29, gossip_msg_29_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_30, gossip_msg_30_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_31, gossip_msg_31_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_32, gossip_msg_32_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_33, gossip_msg_33_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_34, gossip_msg_34_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_35, gossip_msg_35_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_36, gossip_msg_36_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_37, gossip_msg_37_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_38, gossip_msg_38_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_39, gossip_msg_39_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_40, gossip_msg_40_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_41, gossip_msg_41_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_42, gossip_msg_42_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_43, gossip_msg_43_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_44, gossip_msg_44_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_45, gossip_msg_45_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_46, gossip_msg_46_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_47, gossip_msg_47_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_48, gossip_msg_48_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_49, gossip_msg_49_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_50, gossip_msg_50_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_51, gossip_msg_51_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_52, gossip_msg_52_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_53, gossip_msg_53_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_54, gossip_msg_54_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_55, gossip_msg_55_sz ) );
  FD_TEST( test_deserialization_serialization_roundtrip( (uchar *)gossip_msg_56, gossip_msg_56_sz ) );

    /* ContactInfo CRDS objects */
  FD_IMPORT_BINARY( contact_info_crds_1, "src/ballet/gossip/fixtures/contact_info_crds_1.bin" );
  FD_IMPORT_BINARY( contact_info_crds_2, "src/ballet/gossip/fixtures/contact_info_crds_2.bin" );
  FD_IMPORT_BINARY( contact_info_crds_3, "src/ballet/gossip/fixtures/contact_info_crds_3.bin" );
  FD_IMPORT_BINARY( contact_info_crds_4, "src/ballet/gossip/fixtures/contact_info_crds_4.bin" );
  FD_IMPORT_BINARY( contact_info_crds_5, "src/ballet/gossip/fixtures/contact_info_crds_5.bin" );
  FD_IMPORT_BINARY( contact_info_crds_6, "src/ballet/gossip/fixtures/contact_info_crds_6.bin" );
  FD_IMPORT_BINARY( contact_info_crds_7, "src/ballet/gossip/fixtures/contact_info_crds_7.bin" );
  FD_IMPORT_BINARY( contact_info_crds_8, "src/ballet/gossip/fixtures/contact_info_crds_8.bin" );

  /* Because the ContactInfo CRDS object type is not yet active in any public Solana cluster, we don't observe
     any such objects on the wire, hence these are testcases generated by hacking on a testcase in the Rust 
     validator to test the encoding and decoding routines. */
  FD_TEST( test_contactinfo_deserialization_serialization_round_trip( (uchar *)contact_info_crds_1, contact_info_crds_1_sz ) );
  FD_TEST( test_contactinfo_deserialization_serialization_round_trip( (uchar *)contact_info_crds_2, contact_info_crds_2_sz ) );
  FD_TEST( test_contactinfo_deserialization_serialization_round_trip( (uchar *)contact_info_crds_3, contact_info_crds_3_sz ) );
  FD_TEST( test_contactinfo_deserialization_serialization_round_trip( (uchar *)contact_info_crds_4, contact_info_crds_4_sz ) );
  FD_TEST( test_contactinfo_deserialization_serialization_round_trip( (uchar *)contact_info_crds_5, contact_info_crds_5_sz ) );
  FD_TEST( test_contactinfo_deserialization_serialization_round_trip( (uchar *)contact_info_crds_6, contact_info_crds_6_sz ) );
  FD_TEST( test_contactinfo_deserialization_serialization_round_trip( (uchar *)contact_info_crds_7, contact_info_crds_7_sz ) );
  FD_TEST( test_contactinfo_deserialization_serialization_round_trip( (uchar *)contact_info_crds_8, contact_info_crds_8_sz ) );

  FD_TEST( test_contiguous_encoding( (uchar *)gossip_msg_0, gossip_msg_0_sz, (uchar *)gossip_msg_1, gossip_msg_1_sz, (uchar *)gossip_msg_2, gossip_msg_2_sz, (uchar *)gossip_msg_3, gossip_msg_3_sz ));

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
