package ca

import (
	"encoding/json"
	"fmt"
	"github.com/rhine-team/RHINE-Prototype/common"
	"github.com/rhine-team/RHINE-Prototype/requests"
	"log"
	"net/http"
)

func (myca *Ca) NewDlg(w http.ResponseWriter, r *http.Request) {

	logger.Info("CA: Received NewDlg Request")
	preq, err := DecodeNewDlgRequest(r)
	if err != nil {
		log.Println("CA: Error Decoding Request")
		resp := requests.CAResponse{Error: "malformed request"}
		jsonresp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonresp)
		return
	}

	log.Printf("CA: Decoded Request: %#v\n", preq)

	certbytes, CAErr := myca.ProcessNewDlgRequest(*preq)

	if CAErr != nil {
		logger.Warn(fmt.Sprintln("CA: Error Processing NewDlg Req: ", requests.ErrorMsg[CAErr.Code]))
		resp := requests.CAResponse{Error: requests.ErrorMsg[CAErr.Code]}
		log.Printf("CA: NewDlgReq FAILED: Response: %#v", resp)
		jsonresp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonresp)
	} else {
		resp := requests.CAResponse{Cert: common.EncodeBase64(certbytes)}
		log.Printf("CA: NewDlgReq OK: Response: %#v", resp)
		jsonresp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonresp)
	}

}

func (myca *Ca) KeyChangeDlg(w http.ResponseWriter, r *http.Request) {
	log.Println("CA: Received KeyChangeDlg Request")
	req, err := DecodeKeyChangeDlgRequest(r)
	if err != nil {
		log.Println("CA: Error Decoding Request")
		resp := requests.CAResponse{Error: "malformed request"}
		jsonresp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonresp)
		return
	}

	log.Printf("CA: Decoded Request: %#v\n", req)

	certbytes, CAErr := myca.ProcessKeyChangeDlgRequest(*req)

	if CAErr != nil {
		logger.Warn(fmt.Sprintln("CA: Error Processing KeyChangeDlg Req: ", requests.ErrorMsg[CAErr.Code]))
		resp := requests.CAResponse{Error: requests.ErrorMsg[CAErr.Code]}
		log.Printf("CA: KeyChangeDlgReq FAILED: Response: %#v", resp)
		jsonresp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonresp)
	} else {
		resp := requests.CAResponse{Cert: common.EncodeBase64(certbytes)}
		log.Printf("CA: KeyChangeDlgReq OK: Response: %#v", resp)
		jsonresp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonresp)
	}

}

func (myca *Ca) ReNewDlg(w http.ResponseWriter, r *http.Request) {

	log.Println("CA: Received ReNewDlg Request")
	req, err := DecodeReNewDlgRequest(r)
	if err != nil {
		log.Println("CA: Error Decoding Request")
		resp := requests.CAResponse{Error: "malformed request"}
		jsonresp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonresp)
		return
	}

	log.Printf("CA: Decoded Request: %#v\n", req)

	certbytes, CAErr := myca.ProcessReNewDlgRequest(*req)

	if CAErr != nil {
		logger.Warn(fmt.Sprintln("CA: Error Processing ReNewDlg Req: ", requests.ErrorMsg[CAErr.Code]))
		resp := requests.CAResponse{Error: requests.ErrorMsg[CAErr.Code]}
		log.Printf("CA: ReNewDlgReq FAILED: Response: %#v", resp)
		jsonresp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonresp)
	} else {
		resp := requests.CAResponse{Cert: common.EncodeBase64(certbytes)}
		log.Printf("CA: NewDlgReq OK: Response: %#v", resp)
		jsonresp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonresp)
	}

}

func (myca *Ca) RunServer(addr string) {
	http.HandleFunc("/NewDlg", myca.NewDlg)
	http.HandleFunc("/KeyChangeDlg", myca.KeyChangeDlg)
	http.HandleFunc("/ReNewDlg", myca.ReNewDlg)
	log.Fatal(http.ListenAndServe(addr, nil)) // TODO HTTPS

}
