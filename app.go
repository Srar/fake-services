package main

import (
	"fake-services/linked_hashmap"
	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"math"
	"math/rand"
	"sync"
	"time"
)

type Grey struct {
	ExpireAt      time.Time
	AccessedPorts []uint16
}

type Black struct {
	ExpireAt      time.Time
}

var (
	locker    = &sync.Mutex{}
	greyList  = linked_hashmap.NewLinkedHashMap()
	blackList = linked_hashmap.NewLinkedHashMap()
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func main() {
	ifce := flag.String("ifce", "eth0", "")
	flag.Parse()

	pcapHandle, err := pcap.OpenLive(*ifce, 65536, false, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	err = pcapHandle.SetBPFFilter("tcp and tcp[tcpflags] & (tcp-syn) != 0 and ip[8] != 64 and ip[8] != 128 and ip[8] != 32 and ip[8] != 255")
	if err != nil {
		panic(err)
	}

	go listCleaner()
	log.Printf("Listining on interface [%s].", *ifce)
	for {
		data, _, err := pcapHandle.ZeroCopyReadPacketData()
		if err != nil {
			panic(err)
		}

		eth := new(layers.Ethernet)
		ipv4 := new(layers.IPv4)
		tcp := new(layers.TCP)

		var decoded []gopacket.LayerType
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, eth, ipv4, tcp)
		_ = parser.DecodeLayers(data, &decoded)

		if tcp.Ack != 0 {
			continue
		}

		remoteIP := ipv4.SrcIP.To4().String()
		remoteDstPort := uint16(tcp.DstPort)

		locker.Lock()
		// 如果已经在黑名单内发送SYN, ACK伪造包
		if black := blackList.Get(remoteIP); black != nil {
			black.(*Black).ExpireAt = time.Now().Add(time.Minute * 5)
			blackList.Remove(remoteIP)
			blackList.Add(remoteIP, black)
			locker.Unlock()

			l2 := layers.Ethernet{
				SrcMAC:       eth.DstMAC,
				DstMAC:       eth.SrcMAC,
				EthernetType: 0x0800,
			}

			l3 := layers.IPv4{
				SrcIP:    ipv4.DstIP,
				DstIP:    ipv4.SrcIP,
				Version:  4,
				TTL:      64,
				Id:       uint16(rand.Intn(math.MaxUint16)),
				Protocol: layers.IPProtocolTCP,
			}

			l4 := layers.TCP{
				SrcPort: tcp.DstPort,
				DstPort: tcp.SrcPort,
				SYN:     true,
				ACK:     true,
				Seq:     uint32(rand.Intn(99999999-10000000) + 10000000),
				Ack:     tcp.Seq + 1,
				Window:  29200,
				Options: []layers.TCPOption{
					{
						OptionType:   layers.TCPOptionKindMSS,
						OptionLength: 4,
						OptionData:   []byte{0x05, 0x78},
					},
					{
						OptionType:   layers.TCPOptionKindNop,
						OptionLength: 0,
						OptionData:   []byte{},
					},
					{
						OptionType:   layers.TCPOptionKindNop,
						OptionLength: 0,
						OptionData:   []byte{},
					},
					{
						OptionType:   layers.TCPOptionKindSACKPermitted,
						OptionLength: 2,
						OptionData:   []byte{},
					},
					{
						OptionType:   layers.TCPOptionKindNop,
						OptionLength: 0,
						OptionData:   []byte{},
					},
					{
						OptionType:   layers.TCPOptionKindWindowScale,
						OptionLength: 3,
						OptionData:   []byte{0x08},
					},
				},
			}

			l4.SetNetworkLayerForChecksum(&l3)
			packetBuffer := gopacket.NewSerializeBuffer()
			gopacket.SerializeLayers(
				packetBuffer, gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true},
				&l2, &l3, &l4,
			)
			payload := packetBuffer.Bytes()
			pcapHandle.WritePacketData(payload)
			pcapHandle.WritePacketData(payload)
			continue
		}

		var grey *Grey
		if g := greyList.Get(remoteIP); g == nil {
			grey = &Grey{
				AccessedPorts: make([]uint16, 0, 4),
			}
			greyList.Add(remoteIP, grey)
		} else {
			grey = g.(*Grey)
			greyList.Remove(remoteIP)
			greyList.Add(remoteIP, grey)
		}
		grey.ExpireAt = time.Now().Add(10 * time.Second)

		for _, port := range grey.AccessedPorts {
			if port == remoteDstPort {
				goto j
			}
		}
		grey.AccessedPorts = append(grey.AccessedPorts, remoteDstPort)
		if len(grey.AccessedPorts) >= 4 {
			greyList.Remove(remoteIP)
			log.Printf("[%s] hired to blacklist", remoteIP)
			blackList.Add(remoteIP, &Black{ExpireAt: time.Now().Add(time.Minute * 5)})
			goto j
		}

		goto j

		j:
			locker.Unlock()
			continue
	}

}

func listCleaner()  {
	for {
		nowTime := time.Now()

		locker.Lock()

		greyLinklist := greyList.GetLinkList()
		for {
			node := greyLinklist.GetHead()
			if node == nil {
				break
			}

			remoteIP := node.GetVal().(string)
			grey := greyList.Get(remoteIP).(*Grey)
			duration := nowTime.Sub(grey.ExpireAt)

			if duration < 0 {
				break
			}

			nextNode := node.GetNext()
			greyList.Remove(remoteIP)
			node = nextNode
		}

		blackLinklist := blackList.GetLinkList()
		for {
			node := blackLinklist.GetHead()
			if node == nil {
				break
			}

			remoteIP := node.GetVal().(string)
			black := blackList.Get(remoteIP).(*Black)
			duration := nowTime.Sub(black.ExpireAt)

			if duration < 0 {
				break
			}

			nextNode := node.GetNext()
			blackList.Remove(remoteIP)
			log.Printf("[%s] removed from blacklist.", remoteIP)
			node = nextNode
		}

		locker.Unlock()

		time.Sleep(time.Second)
	}
}
