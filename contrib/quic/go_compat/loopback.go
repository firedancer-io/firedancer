package main

import (
	"context"
	"log"
	"net"
	"time"
)

type loopbackPacketConn struct {
	tx chan<- []byte
	rx <-chan []byte

	localAddr *net.UDPAddr
	peerAddr  *net.UDPAddr

	txContext context.Context
	txCancel  context.CancelFunc
	rxContext context.Context
	rxCancel  context.CancelFunc

	log bool
}

func makeLoopbackPacketConnPair(
	leftAddr *net.UDPAddr,
	rightAddr *net.UDPAddr,
	leftToRight chan []byte,
	rightToLeft chan []byte,
) (*loopbackPacketConn, *loopbackPacketConn) {
	peerLeft := &loopbackPacketConn{
		tx:        leftToRight,
		rx:        rightToLeft,
		localAddr: leftAddr,
		peerAddr:  rightAddr,
		txContext: context.Background(),
		txCancel:  func() {},
		rxContext: context.Background(),
		rxCancel:  func() {},
	}
	peerRight := &loopbackPacketConn{
		tx:        rightToLeft,
		rx:        leftToRight,
		localAddr: rightAddr,
		peerAddr:  leftAddr,
		txContext: context.Background(),
		txCancel:  func() {},
		rxContext: context.Background(),
		rxCancel:  func() {},
	}
	return peerLeft, peerRight
}

func (ns *loopbackPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt, ok := <-ns.rx:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n = copy(p, pkt)
		addr = ns.peerAddr
		if ns.log {
			log.Printf("  net: %s <- %s: %4d bytes", ns.localAddr, addr, n)
		}
		return
	case <-ns.rxContext.Done():
		err = ns.rxContext.Err()
		return
	}
}

func (ns *loopbackPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if ns.tx == nil {
		return 0, net.ErrClosed
	}
	p2 := make([]byte, len(p))
	copy(p2, p)
	select {
	case ns.tx <- p2:
		n = len(p2)
		if ns.log {
			log.Printf("  net: %s -> %s: %4d bytes", ns.localAddr, addr, n)
		}
		return
	case <-ns.txContext.Done():
		err = ns.txContext.Err()
		return
	}
}

func (ns *loopbackPacketConn) Close() error {
	ns.txCancel()
	ns.rxCancel()
	ns.tx = nil
	return nil
}

func (ns *loopbackPacketConn) LocalAddr() net.Addr {
	return ns.localAddr
}

func (ns *loopbackPacketConn) SetDeadline(t time.Time) error {
	_ = ns.SetReadDeadline(t)
	_ = ns.SetWriteDeadline(t)
	return nil
}

func (ns *loopbackPacketConn) SetReadDeadline(t time.Time) error {
	ns.rxCancel()
	ns.rxContext, ns.rxCancel = context.WithDeadline(context.Background(), t)
	return nil
}

func (ns *loopbackPacketConn) SetWriteDeadline(t time.Time) error {
	ns.txCancel()
	ns.txContext, ns.txCancel = context.WithDeadline(context.Background(), t)
	return nil
}

var _ net.PacketConn = (*loopbackPacketConn)(nil)
