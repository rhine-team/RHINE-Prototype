package checkerExtension

import (
	"encoding/json"
	"fmt"
	"github.com/rhine-team/RHINE-Prototype/cyrill-k/trustflex/rainsclientlog"
	"github.com/rhine-team/RHINE-Prototype/requests"
	"log"
	"net/http"
	"time"
)

func (c *Checker) CheckNewDlg(w http.ResponseWriter, r *http.Request) {
	req, err := DecodeCheckNewDlgRequest(r)
	if err != nil {
		fmt.Println(err)
		return
	}
	cert, CheckerError := c.ProcessCheckNewDlgRequest(*req)

	if CheckerError != nil {
		logger.Warn(fmt.Sprintln("Checker: Error Processing CheckNewDlg Req: ", requests.ErrorMsg[CheckerError.Code]))
		resp := requests.CheckResponse{Status: "Failed", Error: requests.ErrorMsg[CheckerError.Code]}
		log.Printf("Checker: CheckNewDlgReq FAILED: Response: %#v", resp)
		jsonresp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonresp)
		return
	}

	rainsclientlog.AddToLogServer(cert, c.LogID, c.LogAddress, c.LogPkeyPath)
	time.Sleep(time.Second * 2)
	if err := rainsclientlog.Mapping(c.MapPkeyPath, c.MapID, c.MapAddress, c.LogPkeyPath, c.LogID, c.LogAddress); err != nil {
		log.Println(err)
	}

	resp := requests.CheckResponse{Status: "OK"}
	log.Printf("Checker: CheckNewDlgReq OK: Response: %#v", resp)
	jsonresp, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonresp)
	return
}

func (c *Checker) CheckReNewDlg(w http.ResponseWriter, r *http.Request) {
	req, err := DecodeCheckReNewDlgRequest(r)
	if err != nil {
		fmt.Println(err)
		return
	}
	cert, CheckerError := c.ProcessCheckReNewDlgRequest(*req)

	if CheckerError != nil {
		logger.Warn(fmt.Sprintln("Checker: Error Processing CheckReNewDlg Req: ", requests.ErrorMsg[CheckerError.Code]))
		resp := requests.CheckResponse{Status: "Failed", Error: requests.ErrorMsg[CheckerError.Code]}
		log.Printf("Checker: CheckNewDlgReq FAILED: Response: %#v", resp)
		jsonresp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonresp)
		return
	}

	rainsclientlog.AddToLogServer(cert, c.LogID, c.LogAddress, c.LogPkeyPath)
	time.Sleep(time.Second * 2)
	if err := rainsclientlog.Mapping(c.MapPkeyPath, c.MapID, c.MapAddress, c.LogPkeyPath, c.LogID, c.LogAddress); err != nil {
		log.Println(err)
	}

	resp := requests.CheckResponse{Status: "OK"}
	log.Printf("Checker: CheckNewDlgReq OK: Response: %#v", resp)
	jsonresp, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonresp)
	return
}

func (c *Checker) CheckKeyChangeDlg(w http.ResponseWriter, r *http.Request) {
	req, err := DecodeCheckKeyChangeDlgRequest(r)
	if err != nil {
		fmt.Println(err)
		return
	}
	cert, CheckerError := c.ProcessCheckKeyChangeDlgRequest(*req)

	if CheckerError != nil {
		logger.Warn(fmt.Sprintln("Checker: Error Processing CheckKeyChangeDlg Req: ", requests.ErrorMsg[CheckerError.Code]))
		resp := requests.CheckResponse{Status: "Failed", Error: requests.ErrorMsg[CheckerError.Code]}
		log.Printf("Checker: CheckNewDlgReq FAILED: Response: %#v", resp)
		jsonresp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonresp)
		return
	}

	rainsclientlog.AddToLogServer(cert, c.LogID, c.LogAddress, c.LogPkeyPath)
	time.Sleep(time.Second * 2)
	if err := rainsclientlog.Mapping(c.MapPkeyPath, c.MapID, c.MapAddress, c.LogPkeyPath, c.LogID, c.LogAddress); err != nil {
		log.Println(err)
	}

	resp := requests.CheckResponse{Status: "OK"}
	log.Printf("Checker: CheckNewDlgReq OK: Response: %#v", resp)
	jsonresp, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonresp)
	return
}

func (c *Checker) RevokeDlg(w http.ResponseWriter, r *http.Request) {
	req, err := DecodeRevokeDlgRequest(r)
	if err != nil {
		fmt.Println(err)
		return
	}
	cert, CheckerError := c.ProcessRevokeDlgRequest(*req)

	if CheckerError != nil {
		logger.Warn(fmt.Sprintln("Checker: Error Processing CheckReNewDlg Req: ", requests.ErrorMsg[CheckerError.Code]))
		resp := requests.CheckResponse{Status: "Failed", Error: requests.ErrorMsg[CheckerError.Code]}
		log.Printf("Checker: CheckNewDlgReq FAILED: Response: %#v", resp)
		jsonresp, _ := json.Marshal(resp)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonresp)
		return
	}

	rainsclientlog.RevokeCert(cert, c.MapPkeyPath, c.MapID, c.MapAddress)

	resp := requests.CheckResponse{Status: "OK"}
	log.Printf("Checker: CheckNewDlgReq OK: Response: %#v", resp)
	jsonresp, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonresp)
	return
}

func (c *Checker) RunServer(addr string) {
	logger.Info("CheckerExt: Started")
	http.HandleFunc("/CheckNewDlg", c.CheckNewDlg)
	http.HandleFunc("/CheckReNewDlg", c.CheckReNewDlg)
	http.HandleFunc("/CheckKeyChangeDlg", c.CheckKeyChangeDlg)
	http.HandleFunc("/RevokeDlg", c.RevokeDlg)
	log.Fatal(http.ListenAndServe(addr, nil)) // TODO HTTPS
}
