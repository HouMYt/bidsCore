package bids_core

import "fmt"

func main() {
	IBM := 	NewServer("IBM")
	Apple := NewServer("Apple")
	go Apple.Start()
	go IBM.Start()
	res,err := Apple.Send(Apple.node.NodeTable["IBM"],[]byte("hello"))
	if err!=nil{
		fmt.Println(err)
	}
	fmt.Printf("%v\n",res)
}
