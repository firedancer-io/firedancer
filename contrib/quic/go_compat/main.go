package main

// #cgo CFLAGS: -I../../../build/native/gcc/include
// #cgo LDFLAGS: -L../../../build/native/gcc/lib
// #cgo LDFLAGS: -lfd_quic
// #cgo LDFLAGS: -lfd_waltz
// #cgo LDFLAGS: -lfd_tls
// #cgo LDFLAGS: -lfd_tango
// #cgo LDFLAGS: -lfd_ballet
// #cgo LDFLAGS: -lfd_util
// #cgo LDFLAGS: -lstdc++
// #include <stdlib.h>
// #include <stdio.h>
// #include <firedancer/waltz/quic/fd_quic.h>
// #include <firedancer/waltz/quic/tests/fd_quic_test_helpers.h>
// #include <firedancer/util/net/fd_pcapng.h>
/* extern int fdSendCallback(void *, fd_aio_pkt_info_t *, ulong, ulong *, int); */
import "C"
import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	"golang.org/x/net/ipv4"
)

var enableQlog bool

type qlogWriter struct{}

func (qlogWriter) Write(p []byte) (n int, err error) {
	str := strings.Trim(string(p), "\x00\r\n\t \x1e")
	if str != "" {
		log.Print("  qlog: ", str)
	}
	return len(p), nil
}

func (qlogWriter) Close() error {
	return nil
}

var globFdToGo chan []byte

// wrapDatagram wraps a UDP payload in fake Ethernet, IPv4, and UDP headers.
func wrapDatagram(payload []byte, src *net.UDPAddr, dst *net.UDPAddr, seq *int) []byte {
	buf := make([]byte, 0, 20+8+len(payload))

	// IPv4 header
	buf = buf[:len(buf)+20]
	l3 := buf[len(buf)-20:]
	hdr := ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + 8 + len(payload),
		ID:       *seq,
		TTL:      64,
		Protocol: 17, // UDP
		Src:      src.IP,
		Dst:      dst.IP,
	}
	(*seq)++
	l3Copy, err := hdr.Marshal()
	if err != nil {
		panic(err)
	}
	copy(l3, l3Copy)

	// UDP header
	buf = buf[:len(buf)+8]
	l4 := buf[len(buf)-8:]
	binary.BigEndian.PutUint16(l4[0:2], uint16(src.Port))
	binary.BigEndian.PutUint16(l4[2:4], uint16(dst.Port))
	binary.BigEndian.PutUint16(l4[4:6], uint16(8+len(payload)))
	binary.BigEndian.PutUint16(l4[6:8], 0) // checksum

	// Payload
	buf = append(buf, payload...)
	return buf
}

// unwrapDatagram undoes fd_quic's Ethernet, IPv4, and UDP headers.
func unwrapDatagram(buf []byte) []byte {
	// FIXME doesn't handle variable-size IPv4 headers
	return buf[20+8:]
}

//export fdSendCallback
func fdSendCallback(
	_ctx unsafe.Pointer,
	batchPtr *C.fd_aio_pkt_info_t,
	batchCnt C.ulong,
	_optBatchIdx *C.ulong,
	_flush C.int,
) C.int {
	batch := unsafe.Slice(batchPtr, batchCnt)
	for _, pkt := range batch {
		buf := unsafe.Slice((*byte)(pkt.buf), int(pkt.buf_sz))
		if C.fd_quic_test_pcap != nil {
			C.fd_pcapng_fwrite_pkt(C.fd_log_wallclock(), unsafe.Pointer(pkt.buf), (C.ulong)(pkt.buf_sz), unsafe.Pointer(C.fd_quic_test_pcap))
		}
		select {
		case globFdToGo <- unwrapDatagram(buf):
		default:
		}
	}
	return C.FD_AIO_SUCCESS
}

func clientTest(fdQuic *C.fd_quic_t) {
	log.Print("Testing fd_quic client => quic-go server")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	C.fd_quic_config_anonymous(fdQuic, C.FD_QUIC_ROLE_CLIENT)
	C.fd_quic_init(fdQuic)

	netFdToGo := make(chan []byte, 128)
	netGoToFd := make(chan []byte, 128)
	defer close(netFdToGo)

	addrFd := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8000}
	addrGo := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8001}
	_, udpConnGo := makeLoopbackPacketConnPair(addrFd, addrGo, netFdToGo, netGoToFd)
	udpConnGo.log = true

	var wg sync.WaitGroup
	wg.Add(2)
	defer wg.Wait()

	var streamRcvd uint32

	go func() {
		defer wg.Done()
		defer close(netGoToFd)
		defer udpConnGo.Close()
		cert := genSolanaCert()
		tlsConf := &tls.Config{
			NextProtos:         []string{"solana-tpu"},
			InsecureSkipVerify: true,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				return &cert, nil
			},
		}
		quicConfig := &quic.Config{}
		if enableQlog {
			quicConfig.Tracer = func(ctx context.Context, p logging.Perspective, odcid quic.ConnectionID) *logging.ConnectionTracer {
				return qlog.NewConnectionTracer(qlogWriter{}, p, odcid)
			}
		}
		udpConnGo.SetDeadline(time.Now().Add(3 * time.Second))

		listener, err := quic.Listen(udpConnGo, tlsConf, quicConfig)
		if err != nil {
			log.Fatal("QUIC listener failed: ", err)
		}

		conn, err := listener.Accept(ctx)
		if err != nil {
			log.Fatal("QUIC accept failed: ", err)
		}
		log.Print("quic-go server: connected")
		for {
			var appErr *quic.ApplicationError
			stream, err := conn.AcceptUniStream(ctx)
			if errors.As(err, &appErr) {
				break
			} else if err != nil {
				log.Fatal("QUIC accept stream failed: ", err)
			}
			atomic.AddUint32(&streamRcvd, 1)
			buf, err := io.ReadAll(stream)
			if err != nil {
				log.Fatal("QUIC read stream failed: ", err)
			}
			log.Print("quic-go server: received stream: ", string(buf))
		}
		log.Print("quic-go server: done")
	}()

	globFdToGo = netFdToGo
	go func() {
		defer wg.Done()

		service := func(cond func() bool) bool {
			for !cond() {
				ts := C.fd_log_wallclock()
				var seq int
				select {
				case pkt, ok := <-netGoToFd:
					if !ok {
						return false
					}
					buf := wrapDatagram(pkt, addrGo, addrFd, &seq)
					if C.fd_quic_test_pcap != nil {
						C.fd_pcapng_fwrite_pkt(ts, unsafe.Pointer(unsafe.SliceData(buf)), C.ulong(len(buf)), unsafe.Pointer(C.fd_quic_test_pcap))
					}
					C.fd_quic_process_packet(fdQuic, (*C.uchar)(unsafe.SliceData(buf)), C.ulong(len(buf)), ts)
				case <-ctx.Done():
					return false
				default:
				}

				C.fd_quic_service(fdQuic, ts)
			}
			return true
		}

		quicConn := C.fd_quic_connect(fdQuic, 0x0100007f, C.ushort(addrGo.Port), 0x0100007f, C.ushort(addrFd.Port), C.fd_log_wallclock())
		if quicConn == nil {
			log.Fatal("fd_quic_connect failed")
		}
		if !service(func() bool {
			return quicConn.state != C.FD_QUIC_CONN_STATE_HANDSHAKE && quicConn.state != C.FD_QUIC_CONN_STATE_HANDSHAKE_COMPLETE
		}) {
			log.Fatal("Timed out waiting for connection")
		}
		if quicConn.state != C.FD_QUIC_CONN_STATE_ACTIVE {
			log.Fatal("fd_quic_connect failed")
		}
		log.Print("fd_quic client: connected")
		data := []byte("hello")

		stream := C.fd_quic_conn_new_stream(quicConn)
		if stream == nil {
			log.Fatal("fd_quic_conn_new_stream failed")
		}
		sendRes := C.fd_quic_stream_send(stream, unsafe.Pointer(unsafe.SliceData(data)), C.ulong(len(data)), 1)
		if sendRes != C.FD_QUIC_SUCCESS {
			log.Fatalf("fd_quic_stream_send failed (%d)", sendRes)
		}
		// FIXME this is required because fd_quic sends a CONN_CLOSE before a STREAM frame
		service(func() bool {
			return atomic.LoadUint32(&streamRcvd) == 1
		})
		C.fd_quic_conn_close(quicConn, 0)
		service(func() bool {
			return quicConn.state == C.FD_QUIC_CONN_STATE_INVALID
		})
	}()
}

func serverTest(fdQuic *C.fd_quic_t) {
	log.Print("Testing quic-go client => fd_quic server")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	C.fd_quic_config_anonymous(fdQuic, C.FD_QUIC_ROLE_SERVER)
	fdQuic.config.retry = 1
	fdQuic.config.idle_timeout = 1e9
	C.fd_quic_init(fdQuic)

	netFdToGo := make(chan []byte, 128)
	netGoToFd := make(chan []byte, 128)

	addrFd := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8000}
	addrGo := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8001}
	_, udpConnGo := makeLoopbackPacketConnPair(addrFd, addrGo, netFdToGo, netGoToFd)
	udpConnGo.log = true

	var wg sync.WaitGroup
	wg.Add(2)
	defer wg.Wait()

	globFdToGo = netFdToGo
	go func() {
		defer wg.Done()
		defer close(netFdToGo)
		// Busy poll RX and TX
		// FIXME this could be rewritten blocking style
		for {
			ts := C.fd_log_wallclock()
			var seq int
			select {
			case pkt, ok := <-netGoToFd:
				if !ok {
					return
				}
				buf := wrapDatagram(pkt, addrGo, addrFd, &seq)
				var pin runtime.Pinner
				pin.Pin(&buf[0])
				if C.fd_quic_test_pcap != nil {
					C.fd_pcapng_fwrite_pkt(C.fd_log_wallclock(), unsafe.Pointer(unsafe.SliceData(buf)), C.ulong(len(buf)), unsafe.Pointer(C.fd_quic_test_pcap))
				}
				C.fd_quic_process_packet(fdQuic, (*C.uchar)(unsafe.SliceData(buf)), C.ulong(len(buf)), ts)
				pin.Unpin()
			case <-ctx.Done():
				return
			default:
			}

			C.fd_quic_service(fdQuic, ts)
		}
	}()

	go func() {
		defer wg.Done()
		defer close(netGoToFd)
		defer udpConnGo.Close()
		tlsConf := &tls.Config{
			NextProtos:         []string{"solana-tpu"},
			InsecureSkipVerify: true,
		}
		quicConfig := &quic.Config{}
		if enableQlog {
			quicConfig.Tracer = func(ctx context.Context, p logging.Perspective, odcid quic.ConnectionID) *logging.ConnectionTracer {
				return qlog.NewConnectionTracer(qlogWriter{}, p, odcid)
			}
		}
		udpConnGo.SetDeadline(time.Now().Add(3 * time.Second))
		quicConn, err := quic.Dial(ctx, udpConnGo, addrFd, tlsConf, quicConfig)
		if err != nil {
			log.Fatal("QUIC dial failed: ", err)
		}
		log.Print("quic-go client: connected")
		stream, err := quicConn.OpenUniStream()
		if err != nil {
			panic(err)
		}
		if n, err := stream.Write([]byte("hello")); err != nil || n != 5 {
			panic(err)
		}
		if err := stream.Close(); err != nil {
			panic(err)
		}
		// FIXME this is a cheap way to wait for ACKs to go
		time.Sleep(100 * time.Millisecond)
		quicConn.CloseWithError(0, "bye")
		// FIXME this is a cheap way to wait for ACKs to go
		time.Sleep(100 * time.Millisecond)
		log.Print("quic-go client: done")
	}()
}

func main() {
	flag.BoolVar(&enableQlog, "qlog", false, "enable qlog")
	pcapPath := flag.String("pcap", "", "write pcap file")
	flag.Parse()

	// Call fd_boot
	var argc C.int = 1
	argv0 := C.CString("hello")
	defer C.free(unsafe.Pointer(argv0))
	var argvArr = []*C.char{argv0, nil}
	var argv **C.char = (**C.char)(unsafe.Pointer(&argvArr[0]))
	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(&argc)
	pinner.Pin(&argvArr[0])
	pinner.Pin(&argv)
	C.fd_boot(&argc, &argv)
	C.fd_log_level_logfile_set(0)
	C.fd_log_level_stderr_set(0)

	rng := &C.fd_rng_t{
		idx: 0,
		seq: 0x172046447c516741,
	}

	quic_limits := C.fd_quic_limits_t{
		conn_cnt:           4,
		handshake_cnt:      4,
		conn_id_cnt:        4,
		stream_id_cnt:      64,
		inflight_frame_cnt: 64,
		tx_buf_sz:          1280,
		stream_pool_cnt:    64,
	}
	quic_mem := C.aligned_alloc(C.fd_quic_align(), C.fd_quic_footprint(&quic_limits))
	fdQuic := C.fd_quic_join(C.fd_quic_new(quic_mem, &quic_limits))
	if fdQuic == nil {
		panic("aligned_alloc failed")
	}

	sign_ctx := (*C.fd_tls_test_sign_ctx_t)(C.aligned_alloc(128, C.sizeof_fd_tls_test_sign_ctx_t))
	C.fd_tls_test_sign_ctx(sign_ctx, rng)
	C.fd_quic_config_test_signer(fdQuic, sign_ctx)
	aio_tx := &C.fd_aio_t{
		send_func: (C.fd_aio_send_func_t)(C.fdSendCallback),
	}

	pinner.Pin(aio_tx)
	C.fd_quic_set_aio_net_tx(fdQuic, aio_tx)
	if *pcapPath != "" {
		C.fd_quic_test_pcap = C.fopen(C.CString(*pcapPath), C.CString("wb"))
		if C.fd_quic_test_pcap == nil {
			log.Fatal("fopen failed")
		}
		C.fd_aio_pcapng_start_l3(unsafe.Pointer(C.fd_quic_test_pcap))
	}

	clientTest(fdQuic)
	serverTest(fdQuic)
	time.Sleep(100 * time.Millisecond)

	C.free(C.fd_quic_delete((*C.fd_quic_t)(C.fd_quic_leave(fdQuic))))
	C.free(unsafe.Pointer(sign_ctx))

	if C.fd_quic_test_pcap != nil {
		C.fclose(C.fd_quic_test_pcap)
	}
}
