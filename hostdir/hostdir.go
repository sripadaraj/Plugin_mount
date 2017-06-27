package hostdir

import (
	"fmt"
	"github.com/sripadraj/Volume_plugin/hostdir/drivers"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/go-plugins-helpers/volume"
	"github.com/spf13/cobra"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

const (
	UsernameFlag     = "username"
	PasswordFlag     = "password"
	DomainFlag       = "domain"
	SecurityFlag     = "security"
	FileModeFlag     = "fileMode"
	DirModeFlag      = "dirMode"
	VersionFlag      = "version"
	OptionsFlag      = "options"
	BasedirFlag      = "basedir"
	VerboseFlag      = "verbose"
	AvailZoneFlag    = "az"
	NoResolveFlag    = "noresolve"
	NetRCFlag        = "netrc"
	TCPFlag          = "tcp"
	PortFlag         = "port"
	NameServerFlag   = "nameserver"
	NameFlag         = "name"
	SecretFlag       = "secret"
	ContextFlag      = "context"
	ServerMount      = "servermount"
	EnvSambaUser     = "hostdir_host_USERNAME"
	EnvSambaPass     = "hostdir_host_PASSWORD"
	EnvSambaWG       = "hostdir_host_DOMAIN"
	EnvSambaSec      = "hostdir_host_SECURITY"
	EnvSambaFileMode = "hostdir_host_FILEMODE"
	EnvSambaDirMode  = "hostdir_host_DIRMODE"
	EnvTCP           = "hostdir_TCP_ENABLED"
	EnvTCPAddr       = "hostdir_TCP_ADDR"
	PluginAlias      = "hostdir"
	hostdirHelp     = `
	Volume_plugin (host Volume Driver Plugin)

Provides docker volume support for CIFS.  This plugin can be run multiple times to
support different mount types.

== Volume plugin for all types of mount types ==
	`
)

var (
	rootCmd = &cobra.Command{
		Use:              "Volume_plugin",
		Short:            "Docker volume driver plugin",
		Long:             hostdirHelp,
		PersistentPreRun: setupLogger,
	}

	hostCmd = &cobra.Command{
		Use:   "host",
		Short: "run plugin in host mode",
		Run:   execHOST,
	}
      versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Display current version and build date",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("\nVersion: %s - Built: %s\n\n", Version, BuildDate)
		},
	}
	baseDir          = ""
	Version   string = ""
	BuildDate string = ""
)

func Execute() {
	setupFlags()
	rootCmd.Long = fmt.Sprintf(hostdirHelp, Version, BuildDate)
	rootCmd.AddCommand(versionCmd, hostCmd)
	rootCmd.Execute()
}

func setupFlags() {
	rootCmd.PersistentFlags().StringVar(&baseDir, BasedirFlag, filepath.Join(volume.DefaultDockerRootDirectory, PluginAlias), "Mounted volume base directory")
	rootCmd.PersistentFlags().Bool(TCPFlag, false, "Bind to TCP rather than Unix sockets.  Can also be set via hostdir_TCP_ENABLED")
	rootCmd.PersistentFlags().String(PortFlag, ":8877", "TCP Port if --tcp flag is true.  :PORT for all interfaces or ADDRESS:PORT to bind.")
	rootCmd.PersistentFlags().Bool(VerboseFlag, false, "Turns on verbose logging")

	hostCmd.Flags().StringP(UsernameFlag, "u", "", "Username to use for mounts.  Can also set environment hostdir_host_USERNAME")
	hostCmd.Flags().StringP(PasswordFlag, "p", "", "Password to use for mounts.  Can also set environment hostdir_host_PASSWORD")
	hostCmd.Flags().StringP(DomainFlag, "d", "", "Domain to use for mounts.  Can also set environment hostdir_host_DOMAIN")
	hostCmd.Flags().StringP(SecurityFlag, "s", "", "Security mode to use for mounts (mount.host's sec option). Can also set environment hostdir_host_SECURITY.")
	hostCmd.Flags().StringP(FileModeFlag, "f", "", "Setting access rights for files (mount.host's file_mode option). Can also set environment hostdir_host_FILEMODE.")
	hostCmd.Flags().StringP(DirModeFlag, "z", "", "Setting access rights for folders (mount.host's dir_mode option). Can also set environment hostdir_host_DIRMODE.")
	hostCmd.Flags().StringP(NetRCFlag, "", os.Getenv("HOME"), "The default .netrc location.  Default is the user.home directory")
	hostCmd.Flags().StringP(OptionsFlag, "o", "", "Options passed to Cifs mounts (ex: nounix,uid=433)")

}

func setupLogger(cmd *cobra.Command, args []string) {
	if verbose, _ := cmd.Flags().GetBool(VerboseFlag); verbose {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
}

func execHOST(cmd *cobra.Command, args []string) {
	user := typeOrEnv(cmd, UsernameFlag, EnvSambaUser)
	pass := typeOrEnv(cmd, PasswordFlag, EnvSambaPass)
	domain := typeOrEnv(cmd, DomainFlag, EnvSambaWG)
	security := typeOrEnv(cmd, SecurityFlag, EnvSambaSec)
	fileMode := typeOrEnv(cmd, FileModeFlag, EnvSambaFileMode)
	dirMode := typeOrEnv(cmd, DirModeFlag, EnvSambaDirMode)
	netrc, _ := cmd.Flags().GetString(NetRCFlag)
	options, _ := cmd.Flags().GetString(OptionsFlag)

	creds := drivers.NewHostCredentials(user, pass, domain, security, fileMode, dirMode)

	d := drivers.NewHOSTDriver(rootForType(drivers.HOST), creds, netrc, options)
	if len(user) > 0 {
		startOutput(fmt.Sprintf("HOST :: %s, opts: %s", creds, options))
	} else {
		startOutput(fmt.Sprintf("HOST :: netrc: %s, opts: %s", netrc, options))
	}
	start(drivers.HOST, d)
}

func startOutput(info string) {
	log.Infof("== Volume_plugin :: Version: %s - Built: %s ==", Version, BuildDate)
	log.Infof("Starting %s", info)
}

func typeOrEnv(cmd *cobra.Command, flag, envname string) string {
	val, _ := cmd.Flags().GetString(flag)
	if val == "" {
		val = os.Getenv(envname)
	}
	return val
}

func rootForType(dt drivers.DriverType) string {
	return filepath.Join(baseDir, dt.String())
}

func start(dt drivers.DriverType, driver volume.Driver) {
	h := volume.NewHandler(driver)
	if isTCPEnabled() {
		addr := os.Getenv(EnvTCPAddr)
		if addr == "" {
			addr, _ = rootCmd.PersistentFlags().GetString(PortFlag)
		}
		fmt.Println(h.ServeTCP(dt.String(), addr, nil))
	} else {
		fmt.Println(h.ServeUnix(dt.String(), syscall.Getgid()))
	}
}

func isTCPEnabled() bool {
	if tcp, _ := rootCmd.PersistentFlags().GetBool(TCPFlag); tcp {
		return tcp
	}

	if os.Getenv(EnvTCP) != "" {
		ev, _ := strconv.ParseBool(os.Getenv(EnvTCP))
		fmt.Println(ev)

		return ev
	}
	return false
}
