package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
)

// 这里的string代表一个IP，用户的IP
type ServerVPN struct {
	hostIP     string
	DeviceName string
	OnlineMap  map[string]*UserVPN
	mapLock    sync.RWMutex
}

// 这里的string key为IP|Port|<TCP/UDP>的组合，代表这个用户的某一个程序的源IP与port以及协议
type UserVPN struct {
	DeviceName string
	IP         string
	Port       string
	OnlineMap  map[string]*UserProcess
	mapLock    sync.RWMutex
	servervpn  *ServerVPN
}

/*
* function: 处理认证报文的连接
 */
func (s *ServerVPN) handleChallenge(conn net.Conn) error {
	buff := make([]byte, 4096)
	for {
		n, err := conn.Read(buff)
		if n == 0 {
			//认证结束
			return nil
		}
		if err != nil && err != io.EOF {
			fmt.Println("Conn Read ERR:", err)
			return nil
		}

		if err := s.processChallengeData(buff[:n], conn); err != nil {
			return err
		}
	}
}

func (s *ServerVPN) processChallengeData(data []byte, conn net.Conn) error {
	if len(data) < 8 || !hasValidSignature(data) {
		return nil
	}

	srcIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		fmt.Print(err)
		return err
	}

	s.createUserVPN(srcIP)
	return nil
}

func hasValidSignature(data []byte) bool {
	signature := []byte{0x88, 0x88, 0x88, 0x88, 0x99, 0x99, 0x99, 0x99}
	return bytes.HasPrefix(data, signature)
}

func (s *ServerVPN) createUserVPN(srcIP string) {
	UserVPN := &UserVPN{
		DeviceName: s.DeviceName,
		IP:         srcIP,
		OnlineMap:  make(map[string]*UserProcess),
		servervpn:  s,
	}
	fmt.Println("User challenge handle:" + srcIP)
	s.mapLock.Lock()
	s.OnlineMap[srcIP] = UserVPN
	s.mapLock.Unlock()
}

/*
* function : 处理对应TCP连接，并判断是否是合法用户
 */
func (s *ServerVPN) ProcessTCPRequest(conn net.Conn) {
	srcIP := strings.Split(conn.RemoteAddr().String(), ":")[0]
	srcPort := strings.Split(conn.RemoteAddr().String(), ":")[1]
	if _, ok := s.OnlineMap[srcIP]; !ok {
		return
	}

	userVPN := s.OnlineMap[srcIP]
	userProcessKey := srcIP + "|" + srcPort + "|" + "TCP"
	fmt.Println("CONNECT:" + userProcessKey)

	userProcess := &UserProcess{
		key:              userProcessKey,
		ProtocolType:     "TCP",
		IP_User:          srcIP,
		Port_User:        srcPort,
		Conn_User_to_VPN: conn,
		User_to_VPN_Chan: make(chan []byte, 1024),
		VPN_to_User_Chan: make(chan []byte, 1024),
		userVPN:          userVPN,
		offlineChan:      make(chan int),
		PacpChan:         make(chan int),
	}

	userVPN.mapLock.Lock()
	userVPN.OnlineMap[userProcessKey] = userProcess
	userVPN.mapLock.Unlock()

	//监听对方发送过来的报文并且验证目标地址
	exit := make(chan int)
	go userProcess.online(exit)
	<-exit
}

/*
* function:打开TCP和UDP转发通道
 */
func (s *ServerVPN) ListenUserProcess() {
	lister, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.hostIP, 18889)) //TCP监听18889端口

	if err != nil {
		fmt.Println("net.Listen err:", err)
		return
	}

	defer lister.Close()

	for {
		conn, err := lister.Accept()
		if err != nil {
			fmt.Println("listener accept err:", err)
			continue
		}

		go s.ProcessTCPRequest(conn)
	}

	//监听所有到本服务器的对应IP的IP数据包，实现IP层转发
	// handle, err := pcap.OpenLive(uVPN.DeviceName, 65536, true, pcap.BlockForever)
	// if err != nil {
	// 	fmt.Print(err)
	// 	return
	// }
	// defer handle.Close()

	// filter := "src host " + UserIP
	// err = handle.SetBPFFilter(filter)
	// if err != nil {
	// 	fmt.Print(err)
	// 	return
	// }

	// packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// for packet := range packetSource.Packets() {
	// 	uVPN.ProcessPacket(packet)
	// }

	// return
}

func (s *ServerVPN) StartServer(stopCh chan bool) error {
	//先打开固定的某个端口监听认证报文
	if s.hostIP == "" {
		hostAddresses, err := net.InterfaceAddrs()
		if err != nil {
			return err
		}

		var hostIP net.IP
		for _, addr := range hostAddresses {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				hostIP = ipNet.IP
				break
			}

		}

		if hostIP == nil {
			return fmt.Errorf("未找到非环回 IPv4 地址")
		}

		s.hostIP = hostIP.String()
		//stopListen := make(chan bool)
	}
	fmt.Println("START Server ON :" + s.hostIP)

	go s.StartListenPacket()
	go s.ListenUserProcess()

	for {

	}

	<-stopCh
	//<-stopListen

	return nil
}

/*
* function: 启动服务器，监听认证报文
* @ <>
 */
func (s *ServerVPN) StartListenPacket() error {

	lister, err := net.Listen("tcp", fmt.Sprintf("%s:%d", s.hostIP, 18888))

	if err != nil {
		fmt.Println("net.Listen err:", err)
		return err
	}

	defer lister.Close()

	for {
		conn, err := lister.Accept()
		if err != nil {
			fmt.Println("listener accept err:", err)
			continue
		}
		//处理认证链接
		go s.handleChallenge(conn)
	}
}

/*
* function : 判断TCP或者UDP头部的签名是否合法

func hasValidTCPorUDPSignature(data []byte) bool {
	signature := []byte{0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88}
	return bytes.HasPrefix(data, signature)
}*/

//纠结是监听底层IP数据报文还是在TCP和UDP层上监听报文？如果是前者那么我甚至可以ping通，但是这样就不好利用套接字通信了

/*
* function : 处理监听到的报文,如果程序存在则跳过，否则创建对应程序的
 */
/*
func (uVPN *UserVPN) ProcessPacket(packet gopacket.Packet) {
	ipLayers := packet.Layer(layers.LayerTypeIPv4)
	if ipLayers != nil {
		ip, _ := ipLayers.(*layers.IPv4)

		//对监听到的TCP和UDP包分别进行处理，不会对非TCP，UDP包进行处理
		if ip.Protocol == layers.IPProtocolTCP {
			tcpLayer, err := ipLayers.(*layers.TCP)
			if !err {
				return
			}
			data := tcpLayer.Payload
			//首先判断头部是否包含必要签名
			if !hasValidTCPorUDPSignature(data) {
				return
			}

			//创建对应的ProcessID
			processID := uVPN.IP + "|" + tcpLayer.SrcPort.String() + "|" + "TCP"
			userProcess := &UserProcess{
				ProtocolType: "TCP",
				IP_User:      uVPN.IP,
				Port_User:    int(tcpLayer.SrcPort),
				IP_Dst:       dstIP.String(),
				Port_Dst:     dstPort,
			}

		} else if ip.Protocol == layers.IPProtocolUDP {
			udpLayer, err := ipLayers.(*layers.UDP)
			if !err {
				return
			}
			//首先判断头部是否包含必要签名
			if !hasValidTCPorUDPSignature(udpLayer.Payload) {
				return
			}

		}

		payload := ip.Payload
		if len(payload) >= 8 && payload[0] == 0x88 && payload[1] == 0x88 && payload[2] == 0x88 && payload[3] == 0x88 {
			ip.Payload = payload[24:]
			ip.SrcIP = payload[8:16]
			ip.DstIP = payload[16:24]

			// 发送修改后的数据包到原始目的地
			err := sendPacket(packet, uVPN.DeviceName)
			if err != nil {
				fmt.Println("发送数据包失败:", err)
			}
		}
	}
}
*/
