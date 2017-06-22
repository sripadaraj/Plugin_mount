package Plugin_mount

import (
        "errors"
        "strings"
)

const (
        CreateOpt = "create"
        path = "/tmp/mntdir1"
)

type mount struct {
        name    string
        hostdir string 
        
}

func mountpath() {
        return  path 
}
