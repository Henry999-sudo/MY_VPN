package main

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/ipv4"
)

//39.156.66.14

// 保存了用户的某一个程序的主要通信数据结构
type UserProcess struct {
	key              string
	ProtocolType     string //标识是TCP还是UDP
	IP_User          string
	Port_User        string
	IP_Dst           string
	Port_Dst         string
	Conn_User_to_VPN net.Conn
	Conn_VPN_to_Dst  *ipv4.RawConn
	PacpHandle       *pcap.Handle
	User_to_VPN_Chan chan []byte
	VPN_to_User_Chan chan []byte
	userVPN          *UserVPN
	offlineChan      chan int
	PacpChan         chan int
}

/*
* function : 监听openlive打开的底层pacp
 */
func (uP *UserProcess) ListenPacp() {
	<-uP.PacpChan

	// netaddr, _ := net.ResolveIPAddr("ip4", uP.IP_Dst)
	// fmt.Println("listen packet from ", uP.IP_Dst)

	// conn, err := net.ListenIP("ip4:tcp", netaddr)
	// if err != nil {
	// 	fmt.Println("Error listening:", err.Error())
	// 	os.Exit(1)
	// }
	// ipconn, err := ipv4.NewRawConn(conn)
	// if err != nil {
	// 	fmt.Println("Error listening:", err.Error())
	// 	os.Exit(1)
	// }
	fmt.Println("strat listen packet from" + uP.IP_Dst)
	for {
		buf := make([]byte, 4096)
		hdr, _, controlMessage, _ := uP.Conn_VPN_to_Dst.ReadFrom(buf)

		if hdr.Src.String() != uP.IP_Dst {
			continue
		}
		fmt.Println("receive packet from:", hdr.Src.String(), controlMessage)

		packet := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Default)

		for _, layer := range packet.Layers() {
			fmt.Println(layer.LayerType()) //打印这个包里面每一层的类型
		}

		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if ipv4Layer == nil || tcpLayer == nil {
			continue
		}

		ipv4_, err_ip := ipv4Layer.(*layers.IPv4)
		tcp, err_tcp := tcpLayer.(*layers.TCP)
		if !err_ip || !err_tcp {
			continue
		}
		if ipv4_.SrcIP.String() != uP.IP_Dst {
			continue
		}

		ipv4_.DstIP = net.ParseIP(uP.IP_User)
		ipv4_.Checksum = 0

		options := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		tcp.SetNetworkLayerForChecksum(ipv4_)

		newBuff := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(newBuff, options,
			// 这里可以根据需要添加以太网层或其他层
			ipv4_, tcp, gopacket.Payload(tcp.LayerPayload()))

		outgoingPacketData := newBuff.Bytes()
		uP.VPN_to_User_Chan <- outgoingPacketData
	}

	// 使用gopacket的PacketSource来读取捕获的数据包
	/*
		packetSource := gopacket.NewPacketSource(uP.PacpHandle, uP.PacpHandle.LinkType())
		for packet := range packetSource.Packets() {
			// 检查数据包是否包含IP层
			if packet.NetworkLayer() == nil || packet.NetworkLayer().NetworkFlow().Src().String() != uP.IP_Dst {
				break // 不是我们关心的数据包，跳过
			}
			// 将IP数据报文写入发给用户的CHAN

			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if ipv4Layer == nil || tcpLayer == nil {
				continue
			}

			ipv4_, err_ip := ipv4Layer.(*layers.IPv4)
			tcp, err_tcp := tcpLayer.(*layers.TCP)
			if !err_ip || !err_tcp {
				continue
			}

			fmt.Printf("Source IP: %s\n", ipv4_.SrcIP)
			fmt.Printf("Destination IP: %s\n", ipv4_.DstIP)

			fmt.Printf("Received IP packet from %s\n", ipv4_.SrcIP.String())
			//改变原IP数据报文的目标IP地址然后将其发送到用户地址

			ipv4_.DstIP = net.ParseIP(uP.IP_User)
			ipv4_.Checksum = 0
			options := gopacket.SerializeOptions{
				FixLengths:       true, // Fix the length fields of all layers
				ComputeChecksums: true, // Compute the checksum field of all layers that have a checksum
			}

			tcp.SetNetworkLayerForChecksum(ipv4_)

			newBuff := gopacket.NewSerializeBuffer()
			gopacket.SerializeLayers(newBuff, options,
				// 这里可以根据需要添加以太网层或其他层
				ipv4_, tcp, gopacket.Payload(tcp.LayerPayload()))

			outgoingPacketData := newBuff.Bytes()
			uP.VPN_to_User_Chan <- outgoingPacketData
		}
	*/
}

/*
* function : 监听用户发来数据的管道并且将其发送到目标地址
 */
func (uP *UserProcess) ListenChanFromUser() {
	for buff := range uP.User_to_VPN_Chan {
		//buff是一个完整的IP数据报文，构造一个本机地址到目标地址的IP数据报文，TCP内容不变交给目标地址
		//这里构造IP数据报文然后将这个IP数据报文通过原始套接字发送出去
		//获取数据包的目的地址并判断是否需要重新建立新的连接
		//取出目标地址，端口号判断
		//对方发送过来的是一个完整的封装过的IP数据报文下面对这个IP数据报文进行解析
		fmt.Printf("process data size is %d data : %x\n", len(buff), buff)
		data := buff
		packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)

		for _, layer := range packet.Layers() {
			fmt.Println(layer.LayerType()) //打印这个包里面每一层的类型
		}

		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if ipv4Layer == nil || tcpLayer == nil {
			continue
		}

		ipv4_, err_ip := ipv4Layer.(*layers.IPv4)
		tcp, err_tcp := tcpLayer.(*layers.TCP)
		if !err_ip || !err_tcp {
			continue
		}

		fmt.Printf("Source IP: %s\n", ipv4_.SrcIP)
		fmt.Printf("Destination IP: %s\n", ipv4_.DstIP)

		dstIP := ipv4_.DstIP
		dstPort := tcp.DstPort.String()
		userIP := ipv4_.SrcIP
		userPort := tcp.SrcPort.String()

		if uP.IP_User == "" {
			uP.IP_User = userIP.String()
		} else if uP.IP_User != userIP.String() {
			fmt.Errorf("USERPROCESS USER IP ERROR")
		}

		if uP.Port_User == "" {
			uP.Port_User = userPort
		} else if uP.Port_User != userPort {
			fmt.Errorf("USERPROCESS USER IP ERROR")
		}

		if dstIP.To4() == nil || dstPort == "" {
			fmt.Errorf("Invalid DSTIP OR DSTPORT")
		}

		if uP.Port_Dst != dstPort || uP.IP_Dst != dstIP.String() {
			//建立新的连接
			//这里就是使用原始套接字
			//接着我们需要更改这个数据报文的目标IP和端口号然后通过和VPn网关建立的套接字直接将这个封装过的IP数据报文发送回去
			//这里使用原始套接字发送IP数据报文并且接收IP数据报文，接收的时候利用
			uP.IP_Dst = dstIP.String()
			uP.Port_Dst = dstPort
			// 创建一个原始套接字
			conn1, err := net.ListenPacket("ip4:tcp", uP.userVPN.servervpn.hostIP) // 注意：端口可能不会被使用，因为我们在IP层发送数据
			if err != nil {
				fmt.Println("Error listening:", err.Error())
				os.Exit(1)
			}

			// 转换连接为ipv4.PacketConn以便我们可以设置IP头
			pconn, err := ipv4.NewRawConn(conn1)
			if err != nil {
				fmt.Println("Error getting ipv4 packet conn:", err.Error())
				os.Exit(1)
			}
			uP.Conn_VPN_to_Dst = pconn
			//uP.Conn_VPN_to_Dst.SetBPF()

			// 下面创建监听对应dst的pcap（并使用BPF过滤）
			// 打开设备以捕获数据包
			/*
				fmt.Println("listen device on:" + uP.userVPN.DeviceName)
				// handle, err := pcap.OpenLive(uP.userVPN.DeviceName, 65536, true, pcap.BlockForever)
				handle, err := pcap.OpenLive("ens33", 65536, true, pcap.BlockForever)
				if err != nil {
					fmt.Println("Error opening device:", err)
					os.Exit(1)
				}
				defer handle.Close()

				// 设置BPF过滤器以仅捕获源IP为特定地址的数据包
				// 注意：BPF语法可能与具体的操作系统有关
				filter := "src host " + dstIP.String() // 替换为你想监听的源IP地址
				err = handle.SetBPFFilter(filter)
				if err != nil {
					fmt.Println("Error setting filter:", err)
					os.Exit(1)
				}
				uP.PacpHandle = handle
			*/

			uP.PacpChan <- 1

		}

		//改变原IP数据报文的源IP地址然后将其发送到目标地址

		ipv4_.SrcIP = net.ParseIP(uP.userVPN.servervpn.hostIP)
		ipv4_.Checksum = 0
		// options := gopacket.SerializeOptions{
		// 	FixLengths:       true, // Fix the length fields of all layers
		// 	ComputeChecksums: true, // Compute the checksum field of all layers that have a checksum
		// }
		// newBuff := gopacket.NewSerializeBuffer()
		// gopacket.SerializeLayers(newBuff, options, ipv4_, tcp, tcp.Payload())
		// outgoingPacketData := newBuff.Bytes()
		// 创建新的IPv4层，因为SrcIP是私有的并且不能直接修改
		// newIPv4 := &layers.IPv4{
		// 	Version:    ipv4_.Version,
		// 	IHL:        ipv4_.IHL,
		// 	TOS:        ipv4_.TOS,
		// 	Length:     ipv4_.Length, // 这将在序列化时自动计算
		// 	Id:         ipv4_.Id,     // 你可能需要处理这个字段的唯一性
		// 	Flags:      ipv4_.Flags,
		// 	FragOffset: ipv4_.FragOffset,
		// 	TTL:        ipv4_.TTL,
		// 	Protocol:   ipv4_.Protocol,
		// 	Checksum:   0, // 这将在序列化时自动计算
		// 	SrcIP:      net.ParseIP(uP.userVPN.servervpn.hostIP),
		// 	DstIP:      ipv4_.DstIP,
		// 	Options:    ipv4_.Options,
		// 	Padding:    ipv4_.Padding,
		// }

		// app := packet.ApplicationLayer()
		// if app == nil {
		// 	fmt.Println("app is nil")
		// 	continue
		// }

		// 序列化时可能需要包括以太网层，这取决于你的数据包和网络环境
		// 这里假设我们只关心IP/TCP层，并且正在使用原始套接字
		options := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		tcp.SetNetworkLayerForChecksum(ipv4_)

		newBuff := gopacket.NewSerializeBuffer()
		gopacket.SerializeLayers(newBuff, options,
			// 这里可以根据需要添加以太网层或其他层
			ipv4_, tcp, gopacket.Payload(tcp.LayerPayload()))

		outgoingPacketData := newBuff.Bytes()

		n, err := uP.Conn_VPN_to_Dst.WriteToIP(outgoingPacketData, &net.IPAddr{IP: dstIP})
		if err != nil {
			fmt.Println(err)
		}

		fmt.Printf("SEND Packet to %s size is %d data is :%x\n", dstIP.String(), n, outgoingPacketData)

		// _, err := uP.Conn_VPN_to_Dst.Write(buff[6:])
		// if err != nil {
		// 	fmt.Println("发送数据失败:", err)
		// 	return
		// }
	}
}

/*
* function : 监听用户发送的信息并写入管道，
 */
func (uP *UserProcess) ListenFromUser() {
	buff := make([]byte, 4096)
	for {
		n, err := uP.Conn_User_to_VPN.Read(buff)

		if n == 0 {
			uP.offinle()
			return
		}

		if err != nil && err != io.EOF {
			fmt.Println("Conn Read ERR:", err)
			return
		}

		//uP.User_to_VPN_Chan <- buff
		data := buff[:n]
		fmt.Printf("DATA From User %s :size is %d\n", uP.key, n)
		uP.User_to_VPN_Chan <- data

	}
}

/*
* function : 监听目标地址发来数据的管道并且将其发送到用户地址
 */
func (uP *UserProcess) ListenChanFromDst() {
	for buff := range uP.VPN_to_User_Chan {
		_, err := uP.Conn_User_to_VPN.Write(buff)
		fmt.Printf("send to user %s size is %d\n", uP.key, len(buff))
		if err != nil {
			fmt.Println("发送数据失败:", err)
			return
		}
	}
}

/*
* function : 监听服务器发送过来的消息并对应通道 注意小心这里出现bug

func (uP *UserProcess) ListenFromDST() {
	buff := make([]byte, 4096)

	for {
		if uP.Conn_VPN_to_Dst == nil {
			time.Sleep(time.Duration(time.Duration(3).Seconds())) //zheli
		} else {
			break
		}
	}
	filePath := "output.txt" // 文件路径

	// 创建或打开文件
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Failed to create file:", err)
		return
	}
	defer file.Close()

	for {
		n, err := uP.Conn_VPN_to_Dst.Read(buff)

		if n == 0 {
			uP.offinle()
			return
		}

		if err != nil && err != io.EOF {
			fmt.Println("Conn Read ERR:", err)
			return
		}
		//fmt.Println("DATA From DST " + uP.key + ": " + string(buff))
		_, err = file.WriteString(string(buff))
		if err != nil {
			fmt.Println("Failed to write to file:", err)
			return
		}

		//uP.VPN_to_User_Chan <- buff
		_, err = uP.Conn_User_to_VPN.Write(buff)
		if err != nil {
			fmt.Println("发送数据失败:", err)
			return
		}
	}
}*/

func (uP *UserProcess) offinle() {
	// 销毁对应UserVPN中的选项，并销毁一系列函数
	uP.offlineChan <- 1
	uP.userVPN.mapLock.Lock()
	delete(uP.userVPN.OnlineMap, uP.key)
	uP.userVPN.mapLock.Unlock()
}

/*
* function : 初始化各种监听函数
 */
func (uP *UserProcess) online(exit chan int) {
	go uP.ListenFromUser()
	go uP.ListenChanFromUser()
	go uP.ListenChanFromDst()
	go uP.ListenPacp()

	exit <- 1        //通知调用函数可以结束了
	<-uP.offlineChan //等待消亡信号

}
