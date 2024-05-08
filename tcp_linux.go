//go:build linux
// +build linux

package tcpraw

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	errOpNotImplemented = errors.New("operation not implemented")
	errTimeout          = errors.New("timeout")
	expire              = time.Minute
)

// a message from NIC
type message struct {
	originBufPtr *[]byte
	bts          []byte
	addr         net.Addr
}

// a tcp flow information of a connection pair
type tcpFlow struct {
	conn         *net.TCPConn               // the related system TCP connection of this flow
	handle       *net.IPConn                // the handle to send packets
	seq          uint32                     // TCP sequence number
	ack          uint32                     // TCP acknowledge number
	networkLayer gopacket.SerializableLayer // network layer header for tx
	ts           time.Time                  // last packet incoming time
	buf          gopacket.SerializeBuffer   // a buffer for write
	tcpHeader    layers.TCP
}

// TCPConn defines a TCP-packet oriented connection
type TCPConn struct {
	die     chan struct{}
	dieOnce sync.Once

	// the main golang sockets
	tcpconn  *net.TCPConn     // from net.Dial
	listener *net.TCPListener // from net.Listen

	// handles
	handles []*net.IPConn

	// packets captured from all related NICs will be delivered to this channel
	chMessage chan message

	// all TCP flows
	flowTable map[string]*tcpFlow
	flowsLock sync.Mutex

	// iptables
	iptables *iptables.IPTables
	iprule   []string

	ip6tables *iptables.IPTables
	ip6rule   []string

	// deadlines
	readDeadline  atomic.Value
	writeDeadline atomic.Value

	// serialization
	opts        gopacket.SerializeOptions
	tcpPacketCh chan *packetForChannel
	remoteIP    net.IP
}

// lockflow locks the flow table and apply function `f` to the entry, and create one if not exist
func (conn *TCPConn) lockflow(addr net.Addr, f func(e *tcpFlow)) {
	key := addr.String()
	conn.flowsLock.Lock()
	e := conn.flowTable[key]
	if e == nil { // entry first visit
		e = new(tcpFlow)
		e.ts = time.Now()
		e.buf = gopacket.NewSerializeBuffer()
	}
	f(e)
	conn.flowTable[key] = e
	conn.flowsLock.Unlock()
}

// clean expired flows
func (conn *TCPConn) cleaner() {
	ticker := time.NewTicker(time.Minute)
	select {
	case <-conn.die:
		return
	case <-ticker.C:
		conn.flowsLock.Lock()
		for k, v := range conn.flowTable {
			if time.Now().Sub(v.ts) > expire {
				if v.conn != nil {
					setTTL(v.conn, 64)
					v.conn.Close()
				}
				delete(conn.flowTable, k)
			}
		}
		conn.flowsLock.Unlock()
	}
}

func (conn *TCPConn) captureFlowFromChannel(tcpPacketCh chan *packetForChannel, handle *net.IPConn, remoteIP net.IP) {
	// log.Printf("start capture flow from channel %v", tcpPacketCh)
	for {
		select {
		case packet := <-tcpPacketCh:
			// log.Printf("recv packet from channel")
			conn.handleTCPPacket(handle, packet, remoteIP)
		case <-conn.die:
			close(tcpPacketCh)
			// for {
			// 	select {
			// 	case <-tcpPacketCh:
			// 	default:
			// 		return
			// 	}
			// }
			return
		}
	}
}

// captureFlow capture every inbound packets based on rules of BPF
func (conn *TCPConn) captureFlow(handle *net.IPConn, port int) {
	opt := gopacket.DecodeOptions{NoCopy: true, Lazy: true}
	for {
		bufPtr := bufferPool.Get().(*[]byte)
		buf := *bufPtr
		n, addr, err := handle.ReadFromIP(buf)
		if err != nil {
			return
		}

		// try decoding TCP frame from buf[:n]
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeTCP, opt)
		transport := packet.TransportLayer()
		tcp, ok := transport.(*layers.TCP)
		if !ok {
			continue
		}

		// port filtering
		if int(tcp.DstPort) != port {
			continue
		}

		conn.handleTCPPacket(handle, &packetForChannel{tcp, bufPtr}, addr.IP)
	}
}

func (conn *TCPConn) handleTCPPacket(handle *net.IPConn, packet *packetForChannel, remoteIP net.IP) {
	if packet == nil {
		return
	}
	tcp := packet.tcp
	// address building
	var src net.TCPAddr
	src.IP = remoteIP
	src.Port = int(tcp.SrcPort)

	var orphan bool
	// flow maintaince
	conn.lockflow(&src, func(e *tcpFlow) {
		if e.conn == nil { // make sure it's related to net.TCPConn
			orphan = true // mark as orphan if it's not related net.TCPConn
		}

		// to keep track of TCP header related to this source
		e.ts = time.Now()
		if tcp.ACK {
			e.seq = tcp.Ack
		}
		if tcp.SYN {
			e.ack = tcp.Seq + 1
		}
		if tcp.PSH {
			if e.ack == tcp.Seq {
				e.ack = tcp.Seq + uint32(len(tcp.Payload))
			}
		}
		e.handle = handle
	})

	// push data if it's not orphan
	if !orphan && tcp.PSH {
		select {
		case conn.chMessage <- message{packet.buf, tcp.Payload, &src}:
		case <-conn.die:
			bufferPool.Put(packet.buf)
			return
		}
	}
}

// ReadFrom implements the PacketConn ReadFrom method.
func (conn *TCPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	d := conn.readDeadline.Load()
	if d != nil {
		t := d.(time.Time)
		timer = time.NewTimer(time.Until(t))
		defer timer.Stop()
		deadline = timer.C
	}
	// if d, ok := conn.readDeadline.Load().(time.Time); ok && !d.IsZero() {
	// 	timer = time.NewTimer(time.Until(d))
	// 	defer timer.Stop()
	// 	deadline = timer.C
	// }

	for {
		select {
		case <-deadline:
			d := conn.readDeadline.Load()
			if d != nil {
				t := d.(time.Time)
				if time.Now().After(t) {
					return 0, nil, errTimeout
				} else {
					timer.Reset(time.Until(t))
				}
			}
		case <-conn.die:
			return 0, nil, io.EOF
		case packet := <-conn.chMessage:
			// log.Printf("ReadFrom %d bytes", len(packet.bts))
			n = copy(p, packet.bts)
			bufferPool.Put(packet.originBufPtr)
			return n, packet.addr, nil
		}
	}
}

// WriteTo implements the PacketConn WriteTo method.
func (conn *TCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// log.Printf("prepare to write to %d bytes", len(p))
	var timer *time.Timer
	var deadline <-chan time.Time
	d := conn.writeDeadline.Load()
	if d != nil {
		t := d.(time.Time)
		timer = time.NewTimer(time.Until(t))
		defer timer.Stop()
		deadline = timer.C
	}

SELECT:
	select {
	case <-deadline:
		d := conn.writeDeadline.Load()
		if d != nil {
			t := d.(time.Time)
			if time.Now().After(t) {
				return 0, errTimeout
			} else {
				timer.Reset(time.Until(t))
				goto SELECT
			}
		}
	case <-conn.die:
		return 0, io.EOF
	default:
		raddr, err := net.ResolveTCPAddr("tcp", addr.String())
		if err != nil {
			return 0, err
		}

		var lport int
		if conn.tcpconn != nil {
			lport = conn.tcpconn.LocalAddr().(*net.TCPAddr).Port
		} else {
			lport = conn.listener.Addr().(*net.TCPAddr).Port
		}

		conn.lockflow(addr, func(e *tcpFlow) {
			// log.Printf("write to flow %v", addr.String())
			// if the flow doesn't have handle , assume this packet has lost, without notification
			if e.handle == nil {
				v, ok := handleMap.Load(string(raddr.IP))
				if ok {
					e.handle = v.(*net.IPConn)
				} else {
					log.Printf("flow %v has no handle", addr.String())
					n = len(p)
					return
				}
				log.Printf("flow %v has no handle", addr.String())
				n = len(p)
				return
			}

			// build tcp header with local and remote port
			e.tcpHeader.SrcPort = layers.TCPPort(lport)
			e.tcpHeader.DstPort = layers.TCPPort(raddr.Port)
			binary.Read(rand.Reader, binary.LittleEndian, &e.tcpHeader.Window)
			e.tcpHeader.Window |= 0x8000 // make sure it's larger than 32768
			e.tcpHeader.Ack = e.ack
			e.tcpHeader.Seq = e.seq
			e.tcpHeader.PSH = true
			e.tcpHeader.ACK = true

			// build IP header with src & dst ip for TCP checksum
			if raddr.IP.To4() != nil {
				ip := &layers.IPv4{
					Protocol: layers.IPProtocolTCP,
					SrcIP:    e.handle.LocalAddr().(*net.IPAddr).IP.To4(),
					DstIP:    raddr.IP.To4(),
				}
				e.tcpHeader.SetNetworkLayerForChecksum(ip)
			} else {
				ip := &layers.IPv6{
					NextHeader: layers.IPProtocolTCP,
					SrcIP:      e.handle.LocalAddr().(*net.IPAddr).IP.To16(),
					DstIP:      raddr.IP.To16(),
				}
				e.tcpHeader.SetNetworkLayerForChecksum(ip)
			}

			e.buf.Clear()
			gopacket.SerializeLayers(e.buf, conn.opts, &e.tcpHeader, gopacket.Payload(p))
			// log.Printf("write %d bytes to tcpconn", len(e.buf.Bytes()))
			if conn.tcpconn != nil {
				_, err = e.handle.Write(e.buf.Bytes())
			} else {
				_, err = e.handle.WriteToIP(e.buf.Bytes(), &net.IPAddr{IP: raddr.IP})
			}
			// increase seq in flow
			e.seq += uint32(len(p))
			n = len(p)
		})
	}
	return
}

// Close closes the connection.
func (conn *TCPConn) Close() error {
	var err error
	conn.dieOnce.Do(func() {
		packetChanMap.Delete(conn.tcpconn.LocalAddr().(*net.TCPAddr).Port)

		// signal closing
		close(conn.die)

		// close all established tcp connections
		if conn.tcpconn != nil { // client
			setTTL(conn.tcpconn, 64)
			err = conn.tcpconn.Close()
		} else if conn.listener != nil {
			err = conn.listener.Close() // server
			conn.flowsLock.Lock()
			for k, v := range conn.flowTable {
				if v.conn != nil {
					setTTL(v.conn, 64)
					v.conn.Close()
				}
				delete(conn.flowTable, k)
			}
			conn.flowsLock.Unlock()
		}

		// close handles
		connCount, ok := connCountMap[string(conn.remoteIP)]
		if ok {
			// log.Printf("connCount %v", *connCount)
			atomic.AddInt32(connCount, -1)
			if *connCount == 0 {
				for k := range conn.handles {
					conn.handles[k].Close()
				}
				handleMap.Delete(string(conn.remoteIP))
			}
		}

		// delete iptable
		if conn.iptables != nil {
			conn.iptables.Delete("filter", "OUTPUT", conn.iprule...)
		}
		if conn.ip6tables != nil {
			conn.ip6tables.Delete("filter", "OUTPUT", conn.ip6rule...)
		}
	})
	return err
}

// LocalAddr returns the local network address.
func (conn *TCPConn) LocalAddr() net.Addr {
	if conn.tcpconn != nil {
		return conn.tcpconn.LocalAddr()
	} else if conn.listener != nil {
		return conn.listener.Addr()
	}
	return nil
}

// SetDeadline implements the Conn SetDeadline method.
func (conn *TCPConn) SetDeadline(t time.Time) error {
	if err := conn.SetReadDeadline(t); err != nil {
		return err
	}
	if err := conn.SetWriteDeadline(t); err != nil {
		return err
	}
	return nil
}

// SetReadDeadline implements the Conn SetReadDeadline method.
func (conn *TCPConn) SetReadDeadline(t time.Time) error {
	conn.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (conn *TCPConn) SetWriteDeadline(t time.Time) error {
	conn.writeDeadline.Store(t)
	return nil
}

// SetDSCP sets the 6bit DSCP field in IPv4 header, or 8bit Traffic Class in IPv6 header.
func (conn *TCPConn) SetDSCP(dscp int) error {
	for k := range conn.handles {
		if err := setDSCP(conn.handles[k], dscp); err != nil {
			return err
		}
	}
	return nil
}

// SetReadBuffer sets the size of the operating system's receive buffer associated with the connection.
func (conn *TCPConn) SetReadBuffer(bytes int) error {
	var err error
	for k := range conn.handles {
		if err := conn.handles[k].SetReadBuffer(bytes); err != nil {
			return err
		}
	}
	return err
}

// SetWriteBuffer sets the size of the operating system's transmit buffer associated with the connection.
func (conn *TCPConn) SetWriteBuffer(bytes int) error {
	var err error
	for k := range conn.handles {
		if err := conn.handles[k].SetWriteBuffer(bytes); err != nil {
			return err
		}
	}
	return err
}

type packetForChannel struct {
	tcp *layers.TCP
	buf *[]byte
}

var connCountMap = make(map[string]*int32)
var handleMap = sync.Map{}     // [remoteIP]*net.IPConn
var packetChanMap = sync.Map{} // [localPort]chan *packetForChannel
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 2048)
		return &b
	},
}

func addHandle(handle *net.IPConn, remoteIP net.IP) {
	defer handle.Close()
	defer handleMap.Delete(string(remoteIP))
	log.Printf("add handle %v", handle.RemoteAddr().String())
	opt := gopacket.DecodeOptions{NoCopy: true, Lazy: true}
	for {
		bufPtr := bufferPool.Get().(*[]byte)
		buf := *bufPtr
		n, _, err := handle.ReadFromIP(buf)
		if err != nil {
			log.Printf("handle %v error: %s", handle.RemoteAddr().String(), err)
			return
		}
		// log.Printf("recv %v bytes", n)
		// try decoding TCP frame from buf[:n]
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeTCP, opt)
		transport := packet.TransportLayer()
		tcp, ok := transport.(*layers.TCP)
		if !ok {
			continue
		}
		v, ok := packetChanMap.Load(int(tcp.DstPort))
		if !ok {
			// log.Printf("no channel for port %v", tcp.DstPort)
			bufferPool.Put(bufPtr)
			continue
		}
		tcpPacketCh := v.(chan *packetForChannel)
		// tcpPacketCh := make(chan *packetForChannel, 256)
		// v, ok := packetChanMap.LoadOrStore(int(tcp.DstPort), tcpPacketCh)
		// if !ok {
		// log.Printf("Add channel for port %v [%v]", tcp.DstPort, tcpPacketCh)
		// } else {
		// 	tcpPacketCh = v.(chan *packetForChannel)
		// }
		// log.Printf("send %d bytes to %d [%v]", n, tcp.DstPort, tcpPacketCh)
		select {
		case tcpPacketCh <- &packetForChannel{tcp, bufPtr}:
		default:
			bufferPool.Put(bufPtr)
			log.Printf("channel for port %v is full", tcp.DstPort)
		}
	}
}

func findAvailableTCPAddr() *net.TCPAddr {
	l, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Printf("failed to find available tcp addr: %v", err)
		return nil
	}
	defer l.Close()
	addr := l.Addr().(*net.TCPAddr)
	return addr
}

// Dial connects to the remote TCP port,
// and returns a single packet-oriented connection
func Dial(network, address string) (*TCPConn, error) {
	// remote address resolve
	raddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	v, ok := handleMap.Load(string(raddr.IP))
	var handle *net.IPConn
	if !ok {
		// AF_INET
		handle, err = net.DialIP("ip:tcp", nil, &net.IPAddr{IP: raddr.IP})
		if err != nil {
			return nil, err
		}
		handleMap.Store(string(raddr.IP), handle)
		go addHandle(handle, raddr.IP)
	} else {
		handle = v.(*net.IPConn)
	}

	// create an established tcp connection
	// will hack this tcp connection for packet transmission
	// log.Printf("Dialing to %s", raddr.String())
	// dialer := net.Dialer{
	// 	Timeout: 5 * time.Second, // 设置超时为5秒
	// }
	var tcpconn *net.TCPConn
	var tcpPacketCh chan *packetForChannel
	for i := 0; i < 3; i++ {
		localAddr := findAvailableTCPAddr()
		if localAddr == nil {
			continue
		}
		ch := make(chan *packetForChannel, 256)
		packetChanMap.Store(localAddr.Port, ch)
		dialer := net.Dialer{
			Timeout:   5 * time.Second, // 设置超时时间为5秒
			LocalAddr: localAddr,
		}
		c, err := dialer.Dial(network, raddr.String())
		if err != nil {
			log.Printf("Dial to %s failed: %v", raddr.String(), err)
			packetChanMap.Delete(localAddr.Port)
			close(ch)
			continue
		}
		tcpconn = c.(*net.TCPConn)
		tcpPacketCh = ch
		break
	}
	if tcpconn == nil {
		return nil, err
	}
	// log.Printf("Dial to %s success", raddr.String())
	// tcpconn := c
	// srcPort := tcpconn.LocalAddr().(*net.TCPAddr).Port
	// v2, ok := packetChanMap.LoadOrStore(srcPort, tcpPacketCh)
	// if !ok {
	// log.Printf("Add channel for port %v [%v]", srcPort, tcpPacketCh)
	// } else {
	// 	tcpPacketCh = v2.(chan *packetForChannel)
	// }

	// fields
	conn := new(TCPConn)
	conn.die = make(chan struct{})
	conn.flowTable = make(map[string]*tcpFlow)
	conn.tcpconn = tcpconn
	conn.chMessage = make(chan message)
	conn.lockflow(tcpconn.RemoteAddr(), func(e *tcpFlow) { e.conn = tcpconn })
	conn.handles = append(conn.handles, handle)
	conn.opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	conn.tcpPacketCh = tcpPacketCh
	conn.remoteIP = raddr.IP

	go conn.captureFlowFromChannel(conn.tcpPacketCh, handle, raddr.IP)
	go conn.cleaner()

	connCount, ok := connCountMap[string(raddr.IP)]
	if !ok {
		connCount = new(int32)
		connCountMap[string(raddr.IP)] = connCount
	}
	atomic.AddInt32(connCount, 1)

	// iptables
	err = setTTL(tcpconn, 1)
	if err != nil {
		return nil, err
	}

	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4); err == nil {
		rule := []string{"-m", "ttl", "--ttl-eq", "1", "-p", "tcp", "-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.iprule = rule
					conn.iptables = ipt
				}
			}
		}
	}
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6); err == nil {
		rule := []string{"-m", "hl", "--hl-eq", "1", "-p", "tcp", "-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.ip6rule = rule
					conn.ip6tables = ipt
				}
			}
		}
	}

	// discard everything
	go io.Copy(ioutil.Discard, tcpconn)

	return conn, nil
}

// Listen acts like net.ListenTCP,
// and returns a single packet-oriented connection
func Listen(network, address string) (*TCPConn, error) {
	// fields
	conn := new(TCPConn)
	conn.flowTable = make(map[string]*tcpFlow)
	conn.die = make(chan struct{})
	conn.chMessage = make(chan message)
	conn.opts = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// resolve address
	laddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// AF_INET
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	if laddr.IP == nil || laddr.IP.IsUnspecified() { // if address is not specified, capture on all ifaces
		var lasterr error
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipaddr, ok := addr.(*net.IPNet); ok {
						if handle, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: ipaddr.IP}); err == nil {
							conn.handles = append(conn.handles, handle)
							go conn.captureFlow(handle, laddr.Port)
						} else {
							lasterr = err
						}
					}
				}
			}
		}
		if len(conn.handles) == 0 {
			return nil, lasterr
		}
	} else {
		if handle, err := net.ListenIP("ip:tcp", &net.IPAddr{IP: laddr.IP}); err == nil {
			conn.handles = append(conn.handles, handle)
			go conn.captureFlow(handle, laddr.Port)
		} else {
			return nil, err
		}
	}

	// start listening
	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	conn.listener = l

	// start cleaner
	go conn.cleaner()

	// iptables drop packets marked with TTL = 1
	// TODO: what if iptables is not available, the next hop will send back ICMP Time Exceeded,
	// is this still an acceptable behavior?
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4); err == nil {
		rule := []string{"-m", "ttl", "--ttl-eq", "1", "-p", "tcp", "--sport", fmt.Sprint(laddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.iprule = rule
					conn.iptables = ipt
				}
			}
		}
	}
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6); err == nil {
		rule := []string{"-m", "hl", "--hl-eq", "1", "-p", "tcp", "--sport", fmt.Sprint(laddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.ip6rule = rule
					conn.ip6tables = ipt
				}
			}
		}
	}

	// discard everything in original connection
	go func() {
		for {
			tcpconn, err := l.AcceptTCP()
			if err != nil {
				return
			}

			// if we cannot set TTL = 1, the only thing reasonable is panic
			if err := setTTL(tcpconn, 1); err != nil {
				panic(err)
			}

			// record net.Conn
			conn.lockflow(tcpconn.RemoteAddr(), func(e *tcpFlow) { e.conn = tcpconn })

			// discard everything
			go io.Copy(ioutil.Discard, tcpconn)
		}
	}()

	return conn, nil
}

// setTTL sets the Time-To-Live field on a given connection
func setTTL(c *net.TCPConn, ttl int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	addr := c.LocalAddr().(*net.TCPAddr)

	if addr.IP.To4() == nil {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		})
	} else {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		})
	}
	return err
}

// setDSCP sets the 6bit DSCP field in IPv4 header, or 8bit Traffic Class in IPv6 header.
func setDSCP(c *net.IPConn, dscp int) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	addr := c.LocalAddr().(*net.IPAddr)

	if addr.IP.To4() == nil {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, dscp)
		})
	} else {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, dscp<<2)
		})
	}
	return err
}
