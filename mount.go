package Plugin_mount

import (
	"errors"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/volume"
	"strings"
)

const (
	ShareOpt  = "share"
	CreateOpt = "create"
)
