/* SPDX-License-Identifier: MIT */
/*
 * Author: Jianhui Zhao <zhaojh329@gmail.com>
 */

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/zhaojh329/rttys/v5/utils"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/valyala/bytebufferpool"
)

type CommandReq struct {
	cancel context.CancelFunc
	acked  bool
	c      *gin.Context
}

type CommandReqInfo struct {
	Cmd      string   `json:"cmd"`
	Username string   `json:"username"`
	Params   []string `json:"params"`
}

type CommandRespInfo struct {
	Token string          `json:"token"`
	Attrs json.RawMessage `json:"attrs"`
}

const (
	rttyCmdErrInvalid = 1001
	rttyCmdErrOffline = 1002
	rttyCmdErrTimeout = 1003
)

var cmdErrMsg = map[int]string{
	rttyCmdErrInvalid: "invalid format",
	rttyCmdErrOffline: "device offline",
	rttyCmdErrTimeout: "timeout",
}

func (dev *Device) handleCmdReq(c *gin.Context, info *CommandReqInfo) {
	ctx, cancel := context.WithCancel(dev.ctx)
	defer cancel()

	req := &CommandReq{
		cancel: cancel,
		c:      c,
	}

	token := utils.GenUniqueID()

	msg := bytebufferpool.Get()
	defer bytebufferpool.Put(msg)

	BpWriteCString(msg, info.Username)
	BpWriteCString(msg, info.Cmd)
	BpWriteCString(msg, token)

	msg.WriteByte(byte(len(info.Params)))

	for _, param := range info.Params {
		BpWriteCString(msg, param)
	}

	log.Debug().Msgf("send cmd request for device '%s', token '%s'", dev.id, token)

	err := dev.WriteMsg(msgTypeCmd, "", msg.Bytes())
	if err != nil {
		cmdErrResp(c, rttyCmdErrOffline)
		return
	}

	waitTime := CommandTimeout

	wait := c.Query("wait")
	if wait != "" {
		waitTime, _ = strconv.Atoi(wait)
	}

	if waitTime == 0 {
		c.Status(http.StatusOK)
		return
	}

	dev.commands.Store(token, req)

	if waitTime < 0 || waitTime > CommandTimeout {
		waitTime = CommandTimeout
	}

	tmr := time.NewTimer(time.Second * time.Duration(waitTime))

	log.Debug().Msgf("wait for cmd response for device '%s', token '%s', waitTime %ds", dev.id, token, waitTime)

	select {
	case <-tmr.C:
		cmdErrResp(c, rttyCmdErrTimeout)
	case <-ctx.Done():
	}

	dev.commands.Delete(token)

	if !req.acked {
		cmdErrResp(c, rttyCmdErrOffline)
	}

	log.Debug().Msgf("handle cmd request for device '%s', token '%s' done", dev.id, token)
}

func cmdErrResp(c *gin.Context, err int) {
	c.JSON(http.StatusOK, gin.H{
		"err": err,
		"msg": cmdErrMsg[err],
	})
}

func BpWriteCString(bb *bytebufferpool.ByteBuffer, s string) {
	bb.WriteString(s)
	bb.WriteByte(0)
}
