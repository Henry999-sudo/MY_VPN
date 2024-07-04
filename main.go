package main

func main() {
	serverVPN := &ServerVPN{
		//hostIP:    "127.0.0.1",
		OnlineMap: make(map[string]*UserVPN),
	}
	stop := make(chan bool)
	serverVPN.StartServer(stop)

}
