package main

import (
	"bytes"
	"fmt"
	"net/http"
)

type Server struct {
	url string
	node *Node
	mux *http.ServeMux
}

func NewServer(nodeID string) *Server{
	node := NewNode(nodeID)
	server := &Server{
		url:node.NodeTable[nodeID],
		node: node,
		mux: http.NewServeMux(),
	}
	server.setRoute()
	return server
}
func (server *Server)setRoute(){
	server.mux.HandleFunc("/Block",server.getBlock)
}
func (server *Server)getProposal(writer http.ResponseWriter, request *http.Request){

}
func (server *Server)getCommit(writer http.ResponseWriter, request *http.Request){

}
func (server *Server)getAbstract(writer http.ResponseWriter, request *http.Request){

}
func (server *Server)Send(url string, msg []byte)(*http.Response,error){
	buff := bytes.NewBuffer(msg)
	res,err := http.Post("http://" + url+"/index", "application/json", buff)
	return res,err
}
func (server *Server) Start() {
	fmt.Printf("Server will be started at %s...\n", server.url)
	if err := http.ListenAndServe(server.url, server.mux); err != nil {
		fmt.Println(err)
		return
	}
}