package log

import (
	"github.com/evilsocket/islazy/tui"
)

type FormatConfig struct {
	DateFormat     string
	TimeFormat     string
	DateTimeFormat string
	Format         string
}

var (
	// Effects is a map of the tokens that can be used in Format to
	// change the properties of the text.
	Effects = map[string]string{
		"{bold}":        tui.BOLD,
		"{dim}":         tui.DIM,
		"{red}":         tui.RED,
		"{green}":       tui.GREEN,
		"{blue}":        tui.BLUE,
		"{yellow}":      tui.YELLOW,
		"{f:black}":     tui.FOREBLACK,
		"{f:white}":     tui.FOREWHITE,
		"{b:darkgray}":  tui.BACKDARKGRAY,
		"{b:red}":       tui.BACKRED,
		"{b:green}":     tui.BACKGREEN,
		"{b:yellow}":    tui.BACKYELLOW,
		"{b:lightblue}": tui.BACKLIGHTBLUE,
		"{reset}":       tui.RESET,
	}

	FormatConfigBasic = FormatConfig{
		DateFormat:     dateFormat,
		TimeFormat:     timeFormat,
		DateTimeFormat: dateTimeFormat,
		Format:         format,
	}
	// dateFormat 是填充 {date} 日志标记时使用的默认日期格式
	dateFormat = "06-Jan-02"
	// timeFormat 是填充 {time} 或 {datetime} 日志标记时使用的默认时间格式
	timeFormat = "15:04:05"

	// RFC822
	// DateTimeFormat 是填充 {datetime} 日志令牌时使用的默认日期和时间格式
	dateTimeFormat = "02 Jan 06 15:04 MST"
	// 格式是 log 时使用的默认格式
	format = "{datetime} {level:color}{level:name}{reset} {message}"
)
