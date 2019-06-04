package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
)

type Server struct {
	url      string
	node     *Node
	mux      *http.ServeMux
	msgqueue chan Outmsg
}

func NewServer(node *Node) *Server {
	server := &Server{
		url:  node.NodeTable[node.NodeID],
		node: node,
		mux:  http.NewServeMux(),
	}
	server.msgqueue = make(chan Outmsg)
	server.setRoute()
	return server
}
func (server *Server) setRoute() {
	server.mux.HandleFunc("/Proposal", server.getProposal)
	server.mux.HandleFunc("/Prepare", server.getPrepare)
	server.mux.HandleFunc("/Abort", server.getAbort)
}
func (server *Server) getProposal(writer http.ResponseWriter, request *http.Request) {
	defer writer.Write([]byte("ok"))
	defer request.Body.Close()
	fmt.Println("node " + strconv.Itoa(int(server.node.NodeID)) + " get proposal")
	var proposal Proposal
	buf, err := ioutil.ReadAll(request.Body)
	if err != nil {
		fmt.Println(1)
		fmt.Println(err)
		return
	}
	reader := bytes.NewReader(buf)
	err = proposal.Deserialize(reader)
	if err != nil {
		fmt.Println(2)
		fmt.Println(err)
		return
	}
	proposalok, err := server.node.ProposalVerify(&proposal)
	if err != nil {
		fmt.Println(3)
		fmt.Println(err)
		return
	}
	if !proposalok {
		fmt.Println("proposal verify failed")
		return
	}
	server.node.Prepared[proposal.Abst.Proposer] = proposal
	for _, prepare := range server.node.preparelog[proposal.Abst.Proposer] {
		if prepareok, _ := server.node.VerifyPrepared(prepare); prepareok {

			fmt.Println("node " + strconv.Itoa(int(server.node.NodeID)) + "add prepare ")
			server.node.PreparedNum[proposal.Abst.Proposer] += 1
		}
	}
	prepare, err := server.node.NewPrepared(&proposal)
	if err != nil {
		fmt.Println(4)
		fmt.Println(err)
		return
	}
	var buffer bytes.Buffer
	err = prepare.Serialize(&buffer)
	if err != nil {
		fmt.Println(5)
		fmt.Println(err)
		return
	}
	//fmt.Println("node " + strconv.Itoa(int(server.node.NodeID)) + " sending prepare")
	msg := Outmsg{"Prepare", buffer.Bytes()}
	server.msgqueue <- msg
	//判断prepare数是否满足commit条件
	if server.node.PreparedNum[prepare.Abst.Proposer] > ((len(server.node.NodeTable)-1)/3)*2 {
		fmt.Println("node " + strconv.Itoa(int(server.node.NodeID)) + " commit")
		server.node.PreparedNum[prepare.Abst.Proposer] = 0
		server.node.tops[prepare.Abst.Proposer] = *server.node.Prepared[prepare.Abst.Proposer].Block.Header
		delete(server.node.Prepared, prepare.Abst.Proposer)
		server.node.preparelog[prepare.Abst.Proposer] = []*Prepared{}
		server.node.Done <- struct{}{}
	}


}
func (server *Server) getPrepare(writer http.ResponseWriter, request *http.Request) {
	defer writer.Write([]byte("ok"))
	defer request.Body.Close()
	fmt.Println("node " + strconv.Itoa(int(server.node.NodeID)) + " get prepared")
	var prepare Prepared
	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		fmt.Println(1)
		fmt.Println(err)
		return
	}
	reader := bytes.NewReader(body)
	err = prepare.Deserialize(reader)
	if err != nil {
		fmt.Println(3)
		fmt.Println(err)
		return
	}
	prepareok, err := server.node.VerifyPrepared(&prepare)
	if err != nil {
		server.node.preparelog[prepare.Abst.Proposer] = append(server.node.preparelog[prepare.Abst.Proposer], &prepare)
		fmt.Println(4)
		fmt.Println(err)
		return
	}
	if !prepareok {
		fmt.Println("node " + strconv.Itoa(int(server.node.NodeID)) + " prepare verify failed")
		return
	}

	server.node.PreparedNum[prepare.Abst.Proposer] += 1
	fmt.Printf("node "+strconv.Itoa(int(server.node.NodeID))+" %v prepare\n", server.node.PreparedNum[prepare.Abst.Proposer])
	//判断prepare数是否满足commit条件
	if server.node.PreparedNum[prepare.Abst.Proposer] >((len(server.node.NodeTable)-1)/3)*2{
		fmt.Println("node " + strconv.Itoa(int(server.node.NodeID)) + " commit")
		server.node.PreparedNum[prepare.Abst.Proposer] = 0
		server.node.tops[prepare.Abst.Proposer] = *server.node.Prepared[prepare.Abst.Proposer].Block.Header
		delete(server.node.Prepared, prepare.Abst.Proposer)
		server.node.preparelog[prepare.Abst.Proposer] = []*Prepared{}
		server.node.Done <- struct{}{}
	}

}
func (server *Server) getAbort(writer http.ResponseWriter, request *http.Request) {

}

func (server *Server) Send() {
	for {
		msg := <-server.msgqueue
		for id, url := range server.node.NodeTable {
			if id == server.node.NodeID {
				continue
			}
			reader := bytes.NewReader(msg.Msg)
			fmt.Println("node " + strconv.Itoa(int(server.node.NodeID))+"send "+msg.Type+" to"+strconv.Itoa(int(id)))
			go http.Post("http://"+url+"/"+msg.Type, "text/plain", reader)
		}
	}
}

func (server *Server) Start() {
	fmt.Printf("Server will be started at %s...\n", server.url)
	if err := http.ListenAndServe(server.url, server.mux); err != nil {
		fmt.Println(err)
		return
	}
}
